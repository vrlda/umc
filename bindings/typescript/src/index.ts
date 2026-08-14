import * as net from "node:net";

const DEFAULT_MAX_ENVELOPE = 4 * 1024 * 1024;

export interface Status {
  readonly code: number;
  readonly message: string;
}

export interface Response {
  readonly requestId: bigint;
  readonly status: Status;
  readonly payload: Uint8Array;
}

export class StatusError extends Error {
  readonly status: Status;

  constructor(status: Status) {
    super(`UMC control status ${status.code}${status.message ? `: ${status.message}` : ""}`);
    this.name = "StatusError";
    this.status = status;
  }
}

export class ClientError extends Error {}

interface Field {
  readonly number: number;
  readonly wire: number;
  readonly value: Buffer;
}

function encodeVarint(value: bigint | number): Buffer {
  let current = BigInt(value);
  if (current < 0n) current = BigInt.asUintN(64, current);
  const out: number[] = [];
  do {
    let byte = Number(current & 0x7fn);
    current >>= 7n;
    if (current !== 0n) byte |= 0x80;
    out.push(byte);
  } while (current !== 0n);
  return Buffer.from(out);
}

function fieldKey(number: number, wire: number): Buffer {
  return encodeVarint(BigInt(number << 3 | wire));
}

function bytesField(number: number, value: Uint8Array): Buffer {
  const bytes = Buffer.from(value);
  return Buffer.concat([fieldKey(number, 2), encodeVarint(bytes.length), bytes]);
}

function stringField(number: number, value: string): Buffer {
  return bytesField(number, Buffer.from(value, "utf8"));
}

function varintField(number: number, value: bigint | number): Buffer {
  return Buffer.concat([fieldKey(number, 0), encodeVarint(value)]);
}

function messageField(number: number, value: Buffer): Buffer {
  return bytesField(number, value);
}

function parseVarint(data: Buffer, offset: number): { value: bigint; next: number } {
  let value = 0n;
  for (let index = 0; index < 10; index += 1) {
    if (offset >= data.length) throw new ClientError("truncated protobuf varint");
    const byte = data[offset++];
    value |= BigInt(byte & 0x7f) << BigInt(index * 7);
    if ((byte & 0x80) === 0) return { value, next: offset };
  }
  throw new ClientError("protobuf varint overflow");
}

function fields(data: Buffer): Field[] {
  const result: Field[] = [];
  let offset = 0;
  while (offset < data.length) {
    const key = parseVarint(data, offset);
    offset = key.next;
    const number = Number(key.value >> 3n);
    const wire = Number(key.value & 7n);
    if (number === 0) throw new ClientError("invalid protobuf field number");
    if (wire === 0) {
      const valueStart = offset;
      offset = parseVarint(data, offset).next;
      result.push({ number, wire, value: data.subarray(valueStart, offset) });
    } else if (wire === 2) {
      const length = parseVarint(data, offset);
      offset = length.next;
      const end = offset + Number(length.value);
      if (!Number.isSafeInteger(end) || end > data.length) throw new ClientError("invalid protobuf length");
      result.push({ number, wire, value: data.subarray(offset, end) });
      offset = end;
    } else if (wire === 1) {
      if (offset + 8 > data.length) throw new ClientError("truncated protobuf fixed64");
      result.push({ number, wire, value: data.subarray(offset, offset + 8) });
      offset += 8;
    } else if (wire === 5) {
      if (offset + 4 > data.length) throw new ClientError("truncated protobuf fixed32");
      result.push({ number, wire, value: data.subarray(offset, offset + 4) });
      offset += 4;
    } else {
      throw new ClientError(`unsupported protobuf wire type ${wire}`);
    }
  }
  return result;
}

function firstBytes(data: Buffer, number: number): Buffer | undefined {
  return fields(data).find((field) => field.number === number && field.wire === 2)?.value;
}

function firstVarint(data: Buffer, number: number): bigint | undefined {
  const field = fields(data).find((candidate) => candidate.number === number && candidate.wire === 0);
  return field ? parseVarint(field.value, 0).value : undefined;
}

function encodeVersion(): Buffer {
  return Buffer.concat([varintField(1, 1), varintField(2, 0)]);
}

function encodeHello(clientName: string): Buffer {
  return Buffer.concat([messageField(1, encodeVersion()), stringField(2, clientName)]);
}

function encodeRequest(id: bigint, service: string, method: string, payload: Uint8Array, deadlineUnixMs?: number): Buffer {
  const parts = [varintField(1, id), stringField(2, service), stringField(3, method)];
  if (deadlineUnixMs !== undefined && deadlineUnixMs > 0) parts.push(varintField(4, deadlineUnixMs));
  if (payload.length > 0) parts.push(bytesField(6, payload));
  return Buffer.concat(parts);
}

function encodeEnvelope(bodyField: number, body: Buffer, sequence: bigint): Buffer {
  return Buffer.concat([messageField(1, encodeVersion()), varintField(2, sequence), messageField(bodyField, body)]);
}

function decodeResponse(data: Buffer): Response {
  const requestId = firstVarint(data, 1);
  if (requestId === undefined) throw new ClientError("response omitted request id");
  const statusData = firstBytes(data, 2);
  const status: Status = {
    code: statusData ? Number(firstVarint(statusData, 1) ?? 0n) : 0,
    message: statusData ? (firstBytes(statusData, 2)?.toString("utf8") ?? "") : "",
  };
  return { requestId, status, payload: firstBytes(data, 3) ?? Buffer.alloc(0) };
}

function encodeFrame(payload: Buffer): Buffer {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(payload.length, 0);
  return Buffer.concat([prefix, payload]);
}

class SocketReader {
  private buffer = Buffer.alloc(0);
  private error: Error | undefined;
  private readonly waiters: Array<{ size: number; resolve: (value: Buffer) => void; reject: (error: Error) => void }> = [];

  constructor(private readonly socket: net.Socket) {
    socket.on("data", (chunk: Buffer) => this.feed(chunk));
    socket.on("error", (error) => this.fail(error));
    socket.on("close", () => this.fail(new ClientError("UMC control connection closed")));
  }

  async readExact(size: number): Promise<Buffer> {
    if (size < 0) throw new ClientError("invalid read size");
    if (this.error) throw this.error;
    if (this.buffer.length >= size) {
      const value = this.buffer.subarray(0, size);
      this.buffer = this.buffer.subarray(size);
      return value;
    }
    return new Promise<Buffer>((resolve, reject) => {
      this.waiters.push({ size, resolve, reject });
    });
  }

  private feed(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    this.drain();
  }

  private fail(error: Error): void {
    if (this.error) return;
    this.error = error;
    while (this.waiters.length) this.waiters.shift()?.reject(error);
  }

  private drain(): void {
    while (this.waiters.length && this.buffer.length >= this.waiters[0].size) {
      const waiter = this.waiters.shift()!;
      const value = this.buffer.subarray(0, waiter.size);
      this.buffer = this.buffer.subarray(waiter.size);
      waiter.resolve(value);
    }
  }
}

export interface ClientOptions {
  readonly clientName?: string;
  readonly maxEnvelope?: number;
}

/** Connected UMC Control API client. Endpoint is a Unix socket or Windows named-pipe path. */
export class Client {
  private readonly reader: SocketReader;
  private readonly requestLock: Promise<void> = Promise.resolve();
  private sequence = 1n;
  private requestId = 0n;
  private envelopeMax: number;
  private serial: Promise<void> = Promise.resolve();

  private constructor(private readonly socket: net.Socket, maxEnvelope: number) {
    this.reader = new SocketReader(socket);
    this.envelopeMax = Math.min(DEFAULT_MAX_ENVELOPE, Math.max(1024, maxEnvelope));
  }

  static async connect(endpoint: string, options: ClientOptions = {}): Promise<Client> {
    const socket = await new Promise<net.Socket>((resolve, reject) => {
      const candidate = net.createConnection(endpoint);
      candidate.once("connect", () => resolve(candidate));
      candidate.once("error", reject);
    });
    const client = new Client(socket, options.maxEnvelope ?? DEFAULT_MAX_ENVELOPE);
    try {
      await client.hello(options.clientName ?? "umc-typescript");
      return client;
    } catch (error) {
      socket.destroy();
      throw error;
    }
  }

  async request(service: string, method: string, payload: Uint8Array = new Uint8Array(), deadlineUnixMs?: number): Promise<Response> {
    const previous = this.serial;
    let release!: () => void;
    this.serial = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      this.requestId += 1n;
      const id = this.requestId;
      await this.writeFrame(encodeEnvelope(12, encodeRequest(id, service, method, payload, deadlineUnixMs), this.sequence++));
      for (;;) {
        const envelope = await this.readFrame();
        const responseBody = firstBytes(envelope, 13);
        if (!responseBody) continue;
        const response = decodeResponse(responseBody);
        if (response.requestId === id) return response;
      }
    } finally {
      release();
    }
  }

  async requestChecked(service: string, method: string, payload: Uint8Array = new Uint8Array(), deadlineUnixMs?: number): Promise<Uint8Array> {
    const response = await this.request(service, method, payload, deadlineUnixMs);
    if (response.status.code !== 0) throw new StatusError(response.status);
    return response.payload;
  }

  async getStatus(): Promise<Uint8Array> {
    return this.requestChecked("NodeAdmin", "GetStatus");
  }

  async close(): Promise<void> {
    this.socket.destroy();
  }

  private async hello(clientName: string): Promise<void> {
    await this.writeFrame(encodeEnvelope(10, encodeHello(clientName), this.sequence++));
    const serverHello = firstBytes(await this.readFrame(), 11);
    if (!serverHello) throw new ClientError("UMC Control API hello rejected");
    const selected = firstBytes(serverHello, 1);
    if (!selected || Number(firstVarint(selected, 1) ?? 0n) !== 1) throw new ClientError("unsupported UMC Control API version");
    const negotiated = firstVarint(serverHello, 7);
    if (negotiated !== undefined && negotiated >= 1024n) this.envelopeMax = Math.min(this.envelopeMax, Number(negotiated));
  }

  private async writeFrame(payload: Buffer): Promise<void> {
    if (payload.length === 0 || payload.length > this.envelopeMax) throw new ClientError("invalid UMC envelope size");
    await new Promise<void>((resolve, reject) => {
      this.socket.write(encodeFrame(payload), (error?: Error) => error ? reject(error) : resolve());
    });
  }

  private async readFrame(): Promise<Buffer> {
    const prefix = await this.reader.readExact(4);
    const length = prefix.readUInt32BE(0);
    if (length === 0 || length > this.envelopeMax) throw new ClientError("invalid UMC envelope length");
    return this.reader.readExact(length);
  }
}

/** Encodes ApplicationService.RegisterApplication for use with request(). */
export function registerApplicationRequest(name: string, protocolIds: readonly string[], resumable = false): Uint8Array {
  const parts = [stringField(1, name), ...protocolIds.map((protocolId) => stringField(4, protocolId))];
  if (resumable) parts.push(varintField(6, 1));
  return Buffer.concat(parts);
}
