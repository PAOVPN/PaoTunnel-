package com.example.vpn.ssh

import com.jcraft.jsch.SocketFactory
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets

internal object SshPayloadHelper {

  const val DEFAULT_USER_AGENT =
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

  data class PayloadSegment(
    val bytes: ByteArray,
    val delayAfterMs: Long = 0L,
  )

  private val splitRegex = Regex("\\[(split|delay_split|instant_split)]", RegexOption.IGNORE_CASE)
  private val httpMethodStartRegex =
    Regex("^(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS|CONNECT)\\s+", RegexOption.IGNORE_CASE)

  fun formatPayload(rawTemplate: String, host: String, port: Int): String {
    if (rawTemplate.isBlank()) return ""
    var formatted =
      rawTemplate
        .replace("\\r\\n", "\r\n")
        .replace("\\n\\r", "\n\r")
        .replace("\\r", "\r")
        .replace("\\n", "\n")

    // Normalize bare LF from multiline editors into CRLF before [lf]/[cr] tag expansion
    formatted = Regex("(?<!\r)\n(?!\r)").replace(formatted, "\r\n")

    val rawConnect = "CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\n\r\n"
    formatted =
      formatted
        .replace("[host_port]", "$host:$port", ignoreCase = true)
        .replace("[host]", host, ignoreCase = true)
        .replace("[port]", port.toString(), ignoreCase = true)
        .replace("[protocol]", "HTTP/1.1", ignoreCase = true)
        .replace("[raw]", rawConnect, ignoreCase = true)
        .replace("[real_raw]", rawConnect, ignoreCase = true)
        .replace("[netData]", rawConnect, ignoreCase = true)
        .replace("[ua]", DEFAULT_USER_AGENT, ignoreCase = true)
        .replace("[crlf]", "\r\n", ignoreCase = true)
        .replace("[lfcr]", "\n\r", ignoreCase = true)
        .replace("[cr]", "\r", ignoreCase = true)
        .replace("[lf]", "\n", ignoreCase = true)

    val endsWithSplitTag =
      splitRegex.findAll(formatted).lastOrNull()?.range?.last == formatted.length - 1
    if (!endsWithSplitTag &&
      !formatted.endsWith("\r\n\r\n") &&
      httpMethodStartRegex.containsMatchIn(formatted.trimStart())
    ) {
      formatted = formatted.trimEnd('\r', '\n') + "\r\n\r\n"
    }
    return formatted
  }

  fun splitSegments(formattedPayload: String): List<PayloadSegment> {
    if (formattedPayload.isEmpty()) return emptyList()

    // Step 1: Split on explicit [split], [delay_split], [instant_split] markers
    val primaryChunks = mutableListOf<Pair<String, Long>>()
    val matches = splitRegex.findAll(formattedPayload).toList()
    if (matches.isEmpty()) {
      primaryChunks.add(formattedPayload to 0L)
    } else {
      var cursor = 0
      for (match in matches) {
        val chunk = formattedPayload.substring(cursor, match.range.first)
        val tag = match.groupValues[1].lowercase()
        val delayMs = if (tag == "instant_split") 0L else 100L
        if (chunk.isNotEmpty()) {
          primaryChunks.add(chunk to delayMs)
        }
        cursor = match.range.last + 1
      }
      if (cursor < formattedPayload.length) {
        val tail = formattedPayload.substring(cursor)
        if (tail.isNotEmpty()) {
          primaryChunks.add(tail to 0L)
        }
      }
    }

    // Step 2: Further split concatenated multi-request payloads separated by \r\n\r\n
    val finalSegments = mutableListOf<PayloadSegment>()
    for ((chunk, explicitDelayMs) in primaryChunks) {
      val subRequests = splitConcatenatedHttpRequests(chunk)
      subRequests.forEachIndexed { index, req ->
        val isLastSubRequest = index == subRequests.lastIndex
        val delay =
          when {
            !isLastSubRequest -> 100L
            else -> explicitDelayMs
          }
        if (req.isNotEmpty()) {
          finalSegments.add(PayloadSegment(req.toByteArray(StandardCharsets.UTF_8), delay))
        }
      }
    }
    return finalSegments
  }

  private fun splitConcatenatedHttpRequests(chunk: String): List<String> {
    val result = mutableListOf<String>()
    var start = 0
    while (start < chunk.length) {
      val boundary = chunk.indexOf("\r\n\r\n", startIndex = start)
      if (boundary == -1) {
        val remaining = chunk.substring(start)
        if (remaining.isNotEmpty()) result.add(remaining)
        break
      }
      val endOfRequest = boundary + 4
      val part = chunk.substring(start, endOfRequest)
      val rest = chunk.substring(endOfRequest)
      if (rest.isBlank()) {
        // Trailing whitespace/newlines stay attached to this request
        result.add(chunk.substring(start))
        break
      }
      result.add(part)
      start = endOfRequest
    }
    return result
  }
}

internal class PayloadSocketFactory(
  private val rawPayload: String,
  private val proxyHost: String = "",
  private val proxyPort: Int = 0,
  private val connectTimeoutMs: Int = 15_000,
) : SocketFactory {

  override fun createSocket(host: String, port: Int): Socket {
    val useHttpProxy = proxyHost.isNotBlank() && proxyPort in 1..65535
    val dialHost = if (useHttpProxy) proxyHost.trim() else host
    val dialPort = if (useHttpProxy) proxyPort else port

    val socket = Socket()
    socket.tcpNoDelay = true
    socket.soTimeout = connectTimeoutMs
    socket.connect(InetSocketAddress(dialHost, dialPort), connectTimeoutMs)

    val effectiveTemplate =
      when {
        rawPayload.isNotBlank() -> rawPayload
        useHttpProxy -> "CONNECT [host_port] [protocol][crlf]Host: [host_port][crlf][crlf]"
        else -> ""
      }

    if (effectiveTemplate.isBlank()) {
      socket.soTimeout = 0
      return socket
    }

    val formatted = SshPayloadHelper.formatPayload(effectiveTemplate, host, port)
    val segments = SshPayloadHelper.splitSegments(formatted)
    val out = socket.getOutputStream()
    segments.forEachIndexed { index, segment ->
      out.write(segment.bytes)
      out.flush()
      if (segment.delayAfterMs > 0L && index < segments.lastIndex) {
        Thread.sleep(segment.delayAfterMs)
      }
    }

    val pushbackIn = PushbackInputStream(socket.getInputStream(), 16 * 1024)
    consumeHttpUpgradeResponses(
      socket = socket,
      input = pushbackIn,
      expectedRequests = segments.size.coerceAtLeast(1),
    )
    socket.soTimeout = 0

    return object : Socket() {
      override fun getInputStream(): InputStream = pushbackIn

      override fun getOutputStream(): OutputStream = socket.getOutputStream()

      override fun close() = socket.close()

      override fun isClosed(): Boolean = socket.isClosed

      override fun isConnected(): Boolean = socket.isConnected

      override fun setSoTimeout(timeout: Int) {
        socket.soTimeout = timeout
      }

      override fun getSoTimeout(): Int = socket.soTimeout

      override fun setTcpNoDelay(on: Boolean) {
        socket.tcpNoDelay = on
      }

      override fun getTcpNoDelay(): Boolean = socket.tcpNoDelay

      override fun shutdownInput() = socket.shutdownInput()

      override fun shutdownOutput() = socket.shutdownOutput()
    }
  }

  override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()

  override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()

  internal fun consumeHttpUpgradeResponses(
    socket: Socket?,
    input: PushbackInputStream,
    expectedRequests: Int,
  ) {
    var lastSuccessStatus: String? = null
    var lastErrorStatus: String? = null
    val maxResponses = expectedRequests.coerceAtLeast(1) + 2

    for (attempt in 0 until maxResponses) {
      // If we already got a 2xx response and are peeking for a possible follow-up 101 response
      // (or SSH banner), keep timeout short so we don't stall on servers that wait quietly.
      if (lastSuccessStatus != null && socket != null) {
        socket.soTimeout = 1500
      }

      val peekBuf = ByteArray(4)
      var readCount = 0
      try {
        while (readCount < peekBuf.size) {
          val b = input.read()
          if (b == -1) break
          peekBuf[readCount++] = b.toByte()
        }
      } catch (_: SocketTimeoutException) {
        if (readCount > 0) {
          input.unread(peekBuf, 0, readCount)
        }
        break
      }

      if (readCount == 0) {
        break
      }

      val prefix = String(peekBuf, 0, readCount, StandardCharsets.US_ASCII)
      if (prefix.startsWith("SSH-")) {
        input.unread(peekBuf, 0, readCount)
        return
      }

      if (!prefix.startsWith("HTTP")) {
        if (lastSuccessStatus != null) {
          // Non-HTTP payload after a 200 OK (likely binary/SSH data) -> restore for JSch
          input.unread(peekBuf, 0, readCount)
          return
        }
        // Previous response was a 4xx error with an unframed body; skip until next HTTP/ or SSH-
        val foundMarker = skipUntilHttpOrSshMarker(input, peekBuf, readCount)
        if (!foundMarker) {
          break
        }
        continue
      }

      val headerText = readHttpHeaderBlock(input, peekBuf, readCount)
      val lines = headerText.split(Regex("\r?\n"))
      val statusLine = lines.firstOrNull().orEmpty().trim()
      val statusCode = statusLine.split(Regex("\\s+")).getOrNull(1)?.toIntOrNull()

      if (statusCode != 101) {
        drainHttpBodyIfPresent(input, lines)
      }

      if (statusCode != null && statusCode in 100..299) {
        lastSuccessStatus = statusLine
        if (statusCode == 101) {
          // WebSocket Upgrade complete; hand socket directly to JSch for SSH handshake
          return
        }
        if (attempt + 1 >= expectedRequests) {
          return
        }
      } else if (statusCode != null) {
        // Do NOT fail immediately on 400 Bad Request etc. in multi-request payloads;
        // continue checking subsequent responses for HTTP 101 / 200 OK.
        lastErrorStatus = statusLine
      }
    }

    if (lastSuccessStatus == null && lastErrorStatus != null) {
      throw IOException("SSH payload handshake failed: $lastErrorStatus")
    }
  }

  private fun readHttpHeaderBlock(
    input: PushbackInputStream,
    initialBytes: ByteArray,
    initialLen: Int,
  ): String {
    val headerBuffer = ByteArrayOutputStream()
    headerBuffer.write(initialBytes, 0, initialLen)

    var totalBytes = initialLen
    while (totalBytes < 16_384) {
      val next = input.read()
      if (next == -1) break
      headerBuffer.write(next)
      totalBytes++
      if (next == '\n'.code && endsWithHeaderTerminator(headerBuffer.toByteArray())) {
        break
      }
    }
    return headerBuffer.toString(StandardCharsets.US_ASCII.name())
  }

  private fun drainHttpBodyIfPresent(input: PushbackInputStream, headerLines: List<String>) {
    var contentLength = 0
    var isChunked = false
    for (line in headerLines.drop(1)) {
      val colon = line.indexOf(':')
      if (colon <= 0) continue
      val key = line.substring(0, colon).trim().lowercase()
      val value = line.substring(colon + 1).trim()
      when (key) {
        "content-length" -> contentLength = value.toIntOrNull()?.coerceIn(0, 65_536) ?: 0
        "transfer-encoding" -> if (value.contains("chunked", ignoreCase = true)) isChunked = true
      }
    }

    if (isChunked) {
      drainChunkedBody(input)
    } else if (contentLength > 0) {
      var remaining = contentLength
      val skipBuf = ByteArray(1024)
      while (remaining > 0) {
        val toRead = minOf(remaining, skipBuf.size)
        val n = input.read(skipBuf, 0, toRead)
        if (n <= 0) break
        remaining -= n
      }
    }
  }

  private fun drainChunkedBody(input: PushbackInputStream) {
    var totalDrained = 0
    while (totalDrained < 65_536) {
      val sizeLine = readAsciiLine(input) ?: break
      val chunkSize = sizeLine.substringBefore(';').trim().toIntOrNull(16) ?: break
      if (chunkSize == 0) {
        // Consume final trailing CRLF after 0-byte chunk
        readAsciiLine(input)
        break
      }
      var left = chunkSize
      val buf = ByteArray(1024)
      while (left > 0) {
        val n = input.read(buf, 0, minOf(left, buf.size))
        if (n <= 0) return
        left -= n
        totalDrained += n
      }
      // Consume trailing CRLF of chunk
      readAsciiLine(input)
    }
  }

  private fun readAsciiLine(input: PushbackInputStream): String? {
    val out = ByteArrayOutputStream()
    var count = 0
    while (count < 4096) {
      val b = input.read()
      if (b == -1) return if (out.size() == 0) null else out.toString(StandardCharsets.US_ASCII.name())
      count++
      if (b == '\n'.code) break
      if (b != '\r'.code) out.write(b)
    }
    return out.toString(StandardCharsets.US_ASCII.name())
  }

  private fun skipUntilHttpOrSshMarker(
    input: PushbackInputStream,
    initialBytes: ByteArray,
    initialLen: Int,
  ): Boolean {
    val window = ByteArrayOutputStream()
    window.write(initialBytes, 0, initialLen)
    var scanned = initialLen
    while (scanned < 16_384) {
      val b = input.read()
      if (b == -1) return false
      window.write(b)
      scanned++
      val bytes = window.toByteArray()
      val n = bytes.size
      if (n >= 5 && String(bytes, n - 5, 5, StandardCharsets.US_ASCII) == "HTTP/") {
        input.unread(bytes, n - 5, 5)
        return true
      }
      if (n >= 4 && String(bytes, n - 4, 4, StandardCharsets.US_ASCII) == "SSH-") {
        input.unread(bytes, n - 4, 4)
        return true
      }
    }
    return false
  }

  private fun endsWithHeaderTerminator(bytes: ByteArray): Boolean {
    val n = bytes.size
    if (n >= 4 &&
      bytes[n - 4] == '\r'.code.toByte() &&
      bytes[n - 3] == '\n'.code.toByte() &&
      bytes[n - 2] == '\r'.code.toByte() &&
      bytes[n - 1] == '\n'.code.toByte()
    ) {
      return true
    }
    if (n >= 2 && bytes[n - 2] == '\n'.code.toByte() && bytes[n - 1] == '\n'.code.toByte()) {
      return true
    }
    return false
  }
}
