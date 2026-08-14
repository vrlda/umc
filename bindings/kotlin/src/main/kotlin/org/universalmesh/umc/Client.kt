package org.universalmesh.umc

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.charset.StandardCharsets

public data class Status(val code: Long, val message: String)

public data class Response(val requestId: Long, val status: Status, val payload: ByteArray) {
    override fun equals(other: Any?): Boolean = other is Response && requestId == other.requestId && status == other.status && payload.contentEquals(other.payload)
    override fun hashCode(): Int = 31 * (31 * requestId.hashCode() + status.hashCode()) + payload.contentHashCode()
}

public class StatusException(public val status: Status) : Exception(
    "UMC control status ${status.code}${if (status.message.isEmpty()) "" else ": ${status.message}"}",
)

public class ClientException(message: String) : Exception(message)

private data class Field(val number: Long, val wire: Long, val value: ByteArray)

private object Proto {
    fun varint(value: Long): ByteArray {
        var current = value
        val output = ByteArrayOutputStream()
        do {
            var byte = (current and 0x7f).toInt()
            current = current ushr 7
            if (current != 0L) byte = byte or 0x80
            output.write(byte)
        } while (current != 0L)
        return output.toByteArray()
    }

    fun key(number: Long, wire: Long): ByteArray = varint((number shl 3) or wire)

    fun bytes(number: Long, value: ByteArray): ByteArray = concat(key(number, 2), varint(value.size.toLong()), value)

    fun string(number: Long, value: String): ByteArray = bytes(number, value.toByteArray(StandardCharsets.UTF_8))

    fun integer(number: Long, value: Long): ByteArray = concat(key(number, 0), varint(value))

    fun fields(data: ByteArray): List<Field> {
        val result = mutableListOf<Field>()
        var offset = 0
        while (offset < data.size) {
            val (keyValue, keyLength) = readVarint(data, offset)
            offset += keyLength
            val number = keyValue ushr 3
            val wire = keyValue and 7
            require(number != 0L) { "invalid protobuf field number" }
            when (wire) {
                0L -> {
                    val start = offset
                    offset += readVarint(data, offset).second
                    result += Field(number, wire, data.copyOfRange(start, offset))
                }
                2L -> {
                    val (length, lengthBytes) = readVarint(data, offset)
                    offset += lengthBytes
                    val end = offset + length.toInt()
                    require(length >= 0 && end >= offset && end <= data.size) { "invalid protobuf length" }
                    result += Field(number, wire, data.copyOfRange(offset, end))
                    offset = end
                }
                1L -> {
                    require(offset + 8 <= data.size) { "truncated protobuf fixed64" }
                    result += Field(number, wire, data.copyOfRange(offset, offset + 8))
                    offset += 8
                }
                5L -> {
                    require(offset + 4 <= data.size) { "truncated protobuf fixed32" }
                    result += Field(number, wire, data.copyOfRange(offset, offset + 4))
                    offset += 4
                }
                else -> error("unsupported protobuf wire type $wire")
            }
        }
        return result
    }

    fun bytes(data: ByteArray, number: Long): ByteArray? = fields(data).firstOrNull { it.number == number && it.wire == 2L }?.value

    fun integer(data: ByteArray, number: Long): Long? = fields(data).firstOrNull { it.number == number && it.wire == 0L }?.let { readVarint(it.value, 0).first }

    fun readVarint(data: ByteArray, offset: Int): Pair<Long, Int> {
        var value = 0L
        for (index in 0 until 10) {
            val position = offset + index
            require(position < data.size) { "truncated protobuf varint" }
            val byte = data[position].toInt() and 0xff
            value = value or ((byte and 0x7f).toLong() shl (index * 7))
            if (byte and 0x80 == 0) return value to (index + 1)
        }
        error("protobuf varint overflow")
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        parts.forEach { output.write(it) }
        return output.toByteArray()
    }
}

private fun versionMessage(): ByteArray = Proto.concat(Proto.integer(1, 1), Proto.integer(2, 0))

private fun envelope(bodyField: Long, body: ByteArray, sequence: Long): ByteArray = Proto.concat(
    Proto.bytes(1, versionMessage()),
    Proto.integer(2, sequence),
    Proto.bytes(bodyField, body),
)

private fun helloMessage(clientName: String): ByteArray = Proto.concat(Proto.bytes(1, versionMessage()), Proto.string(2, clientName))

private fun requestMessage(id: Long, service: String, method: String, payload: ByteArray, deadlineUnixMs: Long?): ByteArray {
    val parts = mutableListOf(Proto.integer(1, id), Proto.string(2, service), Proto.string(3, method))
    if (deadlineUnixMs != null && deadlineUnixMs > 0) parts += Proto.integer(4, deadlineUnixMs)
    if (payload.isNotEmpty()) parts += Proto.bytes(6, payload)
    return Proto.concat(*parts.toTypedArray())
}

/** Synchronous Unix-domain UMC Control API client. Payloads use api/umc.proto. */
public class Client private constructor(private val channel: SocketChannel, private val clientName: String) : Closeable {
    private var sequence = 1L
    private var requestId = 0L
    private var envelopeMax = 4 * 1024 * 1024

    init {
        writeFrame(envelope(10, helloMessage(clientName), sequence++))
        val serverHello = Proto.bytes(readFrame(), 11) ?: throw ClientException("UMC Control API hello rejected")
        val selected = Proto.bytes(serverHello, 1) ?: throw ClientException("hello omitted selected version")
        if (Proto.integer(selected, 1) != 1L) throw ClientException("unsupported UMC Control API version")
        Proto.integer(serverHello, 7)?.takeIf { it >= 1024 }?.let { envelopeMax = minOf(envelopeMax, it.toInt()) }
    }

    public companion object {
        @JvmStatic
        public fun connect(unixPath: String, clientName: String = "umc-kotlin"): Client {
            val channel = SocketChannel.open(java.net.StandardProtocolFamily.UNIX)
            channel.connect(UnixDomainSocketAddress.of(unixPath))
            return try {
                Client(channel, clientName)
            } catch (error: Throwable) {
                channel.close()
                throw error
            }
        }

        @JvmStatic
        public fun registerApplicationRequest(name: String, protocolIds: List<String>, resumable: Boolean = false): ByteArray {
            val parts = mutableListOf(Proto.string(1, name))
            protocolIds.forEach { parts += Proto.string(4, it) }
            if (resumable) parts += Proto.integer(6, 1)
            return Proto.concat(*parts.toTypedArray())
        }
    }

    @Synchronized
    public fun request(service: String, method: String, payload: ByteArray = ByteArray(0), deadlineUnixMs: Long? = null): Response {
        requestId += 1
        val id = requestId
        writeFrame(envelope(12, requestMessage(id, service, method, payload, deadlineUnixMs), sequence++))
        while (true) {
            val responseData = Proto.bytes(readFrame(), 13) ?: continue
            val responseID = Proto.integer(responseData, 1) ?: throw ClientException("response omitted request id")
            if (responseID != id) continue
            val statusData = Proto.bytes(responseData, 2)
            val status = Status(
                statusData?.let { Proto.integer(it, 1) } ?: 0,
                statusData?.let { Proto.bytes(it, 2)?.toString(StandardCharsets.UTF_8) } ?: "",
            )
            return Response(responseID, status, Proto.bytes(responseData, 3) ?: ByteArray(0))
        }
    }

    public fun requestChecked(service: String, method: String, payload: ByteArray = ByteArray(0), deadlineUnixMs: Long? = null): ByteArray {
        val response = request(service, method, payload, deadlineUnixMs)
        if (response.status.code != 0L) throw StatusException(response.status)
        return response.payload
    }

    public fun getStatus(): ByteArray = requestChecked("NodeAdmin", "GetStatus")

    override fun close() { channel.close() }

    private fun writeFrame(payload: ByteArray) {
        require(payload.isNotEmpty() && payload.size <= envelopeMax) { "invalid UMC envelope size" }
        val frame = ByteBuffer.allocate(4 + payload.size).putInt(payload.size).put(payload).flip() as ByteBuffer
        while (frame.hasRemaining()) channel.write(frame)
    }

    private fun readFrame(): ByteArray {
        val prefix = readExact(4).also { require(it.size == 4) }
        val length = ByteBuffer.wrap(prefix).int
        require(length > 0 && length <= envelopeMax) { "invalid UMC envelope length" }
        return readExact(length)
    }

    private fun readExact(size: Int): ByteArray {
        val output = ByteBuffer.allocate(size)
        while (output.hasRemaining() && channel.read(output) > 0) {}
        if (output.hasRemaining()) throw ClientException("UMC control connection closed")
        return output.array()
    }
}
