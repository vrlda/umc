import Foundation

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public struct Status: Sendable {
    public let code: UInt64
    public let message: String
}

public struct Response: Sendable {
    public let requestID: UInt64
    public let status: Status
    public let payload: Data
}

public enum ClientError: Error, Equatable {
    case closed
    case invalidFrame
    case invalidProtobuf
    case unsupportedVersion
    case status(StatusCode)
    case io(String)
}

public struct StatusCode: Equatable, Sendable {
    public let code: UInt64
    public let message: String
}

private struct Field {
    let number: UInt64
    let wire: UInt64
    let value: Data
}

private enum Proto {
    static func varint(_ value: UInt64) -> Data {
        var value = value
        var output = Data()
        repeat {
            var byte = UInt8(value & 0x7f)
            value >>= 7
            if value != 0 { byte |= 0x80 }
            output.append(byte)
        } while value != 0
        return output
    }

    static func key(_ number: UInt64, _ wire: UInt64) -> Data {
        return varint(number << 3 | wire)
    }

    static func bytes(_ number: UInt64, _ value: Data) -> Data {
        var output = key(number, 2)
        output.append(varint(UInt64(value.count)))
        output.append(value)
        return output
    }

    static func string(_ number: UInt64, _ value: String) -> Data {
        bytes(number, Data(value.utf8))
    }

    static func integer(_ number: UInt64, _ value: UInt64) -> Data {
        var output = key(number, 0)
        output.append(varint(value))
        return output
    }

    static func fields(_ data: Data) throws -> [Field] {
        var fields: [Field] = []
        var offset = 0
        while offset < data.count {
            let (keyValue, keyLength) = try readVarint(data, offset: offset)
            offset += keyLength
            let number = keyValue >> 3
            let wire = keyValue & 7
            guard number != 0 else { throw ClientError.invalidProtobuf }
            switch wire {
            case 0:
                let start = offset
                let (_, length) = try readVarint(data, offset: offset)
                offset += length
                fields.append(Field(number: number, wire: wire, value: data.subdata(in: start..<offset)))
            case 2:
                let (length, lengthBytes) = try readVarint(data, offset: offset)
                offset += lengthBytes
                guard length <= UInt64(data.count - offset) else { throw ClientError.invalidProtobuf }
                let end = offset + Int(length)
                fields.append(Field(number: number, wire: wire, value: data.subdata(in: offset..<end)))
                offset = end
            case 1:
                guard offset + 8 <= data.count else { throw ClientError.invalidProtobuf }
                fields.append(Field(number: number, wire: wire, value: data.subdata(in: offset..<(offset + 8))))
                offset += 8
            case 5:
                guard offset + 4 <= data.count else { throw ClientError.invalidProtobuf }
                fields.append(Field(number: number, wire: wire, value: data.subdata(in: offset..<(offset + 4))))
                offset += 4
            default:
                throw ClientError.invalidProtobuf
            }
        }
        return fields
    }

    static func bytes(_ data: Data, field number: UInt64) throws -> Data? {
        try fields(data).first { $0.number == number && $0.wire == 2 }?.value
    }

    static func integer(_ data: Data, field number: UInt64) throws -> UInt64? {
        guard let field = try fields(data).first(where: { $0.number == number && $0.wire == 0 }) else { return nil }
        return try readVarint(field.value, offset: 0).0
    }

    private static func readVarint(_ data: Data, offset: Int) throws -> (UInt64, Int) {
        var value: UInt64 = 0
        for index in 0..<10 {
            let position = offset + index
            guard position < data.count else { throw ClientError.invalidProtobuf }
            let byte = data[position]
            value |= UInt64(byte & 0x7f) << UInt64(index * 7)
            if byte & 0x80 == 0 { return (value, index + 1) }
        }
        throw ClientError.invalidProtobuf
    }
}

private func versionMessage() -> Data {
    Proto.integer(1, 1) + Proto.integer(2, 0)
}

private func envelope(bodyField: UInt64, body: Data, sequence: UInt64) -> Data {
    Proto.bytes(1, versionMessage()) + Proto.integer(2, sequence) + Proto.bytes(bodyField, body)
}

private func helloMessage(clientName: String) -> Data {
    Proto.bytes(1, versionMessage()) + Proto.string(2, clientName)
}

private func requestMessage(id: UInt64, service: String, method: String, payload: Data, deadline: Int64?) -> Data {
    var result = Proto.integer(1, id) + Proto.string(2, service) + Proto.string(3, method)
    if let deadline, deadline > 0 { result.append(Proto.integer(4, UInt64(deadline))) }
    if !payload.isEmpty { result.append(Proto.bytes(6, payload)) }
    return result
}

private func makeSocket() -> Int32 {
#if canImport(Darwin)
    return Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
#else
    return Glibc.socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
#endif
}

private func closeSocket(_ fd: Int32) {
#if canImport(Darwin)
    _ = Darwin.close(fd)
#else
    _ = Glibc.close(fd)
#endif
}

/// Synchronous Unix-domain Control API client. Payloads use api/umc.proto.
public final class Client: @unchecked Sendable {
    private var fd: Int32
    private var sequence: UInt64 = 1
    private var requestID: UInt64 = 0
    private var envelopeMax = 4 * 1024 * 1024

    public init(unixPath: String, clientName: String = "umc-swift") throws {
        let socket = makeSocket()
        guard socket >= 0 else { throw ClientError.io("socket failed") }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(unixPath.utf8) + [0]
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count <= capacity else {
            closeSocket(socket)
            throw ClientError.io("Unix socket path is too long")
        }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: pathBytes)
        }
        let length = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
#if canImport(Darwin)
                Darwin.connect(socket, rebound, length)
#else
                Glibc.connect(socket, rebound, length)
#endif
            }
        }
        guard connected == 0 else {
            closeSocket(socket)
            throw ClientError.io("connect failed")
        }
        fd = socket
        try sendFrame(envelope(bodyField: 10, body: helloMessage(clientName: clientName), sequence: sequence))
        sequence += 1
        let serverHello = try Proto.bytes(readFrame(), field: 11)
        guard let serverHello, let selected = try Proto.bytes(serverHello, field: 1), try Proto.integer(selected, field: 1) == 1 else {
            close()
            throw ClientError.unsupportedVersion
        }
        if let negotiated = try Proto.integer(serverHello, field: 7), negotiated >= 1024 {
            envelopeMax = min(envelopeMax, Int(negotiated))
        }
    }

    deinit { close() }

    public func close() {
        if fd >= 0 { closeSocket(fd); fd = -1 }
    }

    public func request(service: String, method: String, payload: Data = Data(), deadlineUnixMs: Int64? = nil) throws -> Response {
        guard fd >= 0 else { throw ClientError.closed }
        requestID += 1
        let id = requestID
        let body = requestMessage(id: id, service: service, method: method, payload: payload, deadline: deadlineUnixMs)
        try sendFrame(envelope(bodyField: 12, body: body, sequence: sequence))
        sequence += 1
        while true {
            let frame = try readFrame()
            guard let responseData = try Proto.bytes(frame, field: 13) else { continue }
            guard let responseID = try Proto.integer(responseData, field: 1), responseID == id else { continue }
            let statusData = try Proto.bytes(responseData, field: 2)
            let status = Status(code: statusData.flatMap { try? Proto.integer($0, field: 1) } ?? 0,
                                message: statusData.flatMap { try? Proto.bytes($0, field: 2) }.map { String(decoding: $0, as: UTF8.self) } ?? "")
            return Response(requestID: responseID, status: status, payload: try Proto.bytes(responseData, field: 3) ?? Data())
        }
    }

    public func requestChecked(service: String, method: String, payload: Data = Data(), deadlineUnixMs: Int64? = nil) throws -> Data {
        let response = try request(service: service, method: method, payload: payload, deadlineUnixMs: deadlineUnixMs)
        guard response.status.code == 0 else {
            throw ClientError.status(StatusCode(code: response.status.code, message: response.status.message))
        }
        return response.payload
    }

    public func getStatus() throws -> Data {
        try requestChecked(service: "NodeAdmin", method: "GetStatus")
    }

    public static func registerApplicationRequest(name: String, protocolIDs: [String], resumable: Bool = false) -> Data {
        var result = Proto.string(1, name)
        for protocolID in protocolIDs { result.append(Proto.string(4, protocolID)) }
        if resumable { result.append(Proto.integer(6, 1)) }
        return result
    }

    private func sendFrame(_ payload: Data) throws {
        guard payload.count > 0 && payload.count <= envelopeMax else { throw ClientError.invalidFrame }
        var prefix = Data([0, 0, 0, 0])
        prefix[0] = UInt8((payload.count >> 24) & 0xff)
        prefix[1] = UInt8((payload.count >> 16) & 0xff)
        prefix[2] = UInt8((payload.count >> 8) & 0xff)
        prefix[3] = UInt8(payload.count & 0xff)
        try writeAll(prefix + payload)
    }

    private func readFrame() throws -> Data {
        let prefix = try readExact(4)
        let length = Int(prefix[0]) << 24 | Int(prefix[1]) << 16 | Int(prefix[2]) << 8 | Int(prefix[3])
        guard length > 0 && length <= envelopeMax else { throw ClientError.invalidFrame }
        return try readExact(length)
    }

    private func writeAll(_ data: Data) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < data.count {
#if canImport(Darwin)
                let written = Darwin.write(fd, base.advanced(by: offset), data.count - offset)
#else
                let written = Glibc.write(fd, base.advanced(by: offset), data.count - offset)
#endif
                guard written > 0 else { throw ClientError.io("write failed") }
                offset += written
            }
        }
    }

    private func readExact(_ count: Int) throws -> Data {
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < count {
#if canImport(Darwin)
                let read = Darwin.read(fd, base.advanced(by: offset), count - offset)
#else
                let read = Glibc.read(fd, base.advanced(by: offset), count - offset)
#endif
                guard read > 0 else { throw ClientError.io("read failed") }
                offset += read
            }
        }
        return data
    }
}

private func + (lhs: Data, rhs: Data) -> Data {
    var result = lhs
    result.append(rhs)
    return result
}
