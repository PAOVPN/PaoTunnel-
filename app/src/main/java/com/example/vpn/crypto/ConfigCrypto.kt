package com.example.vpn.crypto

import com.example.vpn.model.VpnProtocol
import com.example.vpn.model.VpnServer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM encryption and integrity protection for locked PAO Tunnel configs (`paolock://...`).
 * Uses pure-Kotlin Base64URL encoding/decoding so it runs identically on Android API 24+ and JVM tests.
 */
object ConfigCrypto {

  const val LOCKED_SCHEME = "paolock://"
  private const val VERSION_BYTE: Byte = 0x01
  private const val IV_LENGTH = 12
  private const val TAG_BITS = 128
  private const val TRANSFORMATION = "AES/GCM/NoPadding"

  private val secureRandom = SecureRandom()

  private val secretKeySpec: SecretKeySpec by lazy {
    val seedParts =
      listOf(
        "PAO-TUNNEL",
        "CONFIG-VAULT",
        "AES256-GCM",
        "MM-SG-TH-2026",
      )
    val digest = MessageDigest.getInstance("SHA-256")
    seedParts.forEach { part ->
      digest.update(part.toByteArray(StandardCharsets.UTF_8))
      digest.update(0x1F)
    }
    SecretKeySpec(digest.digest(), "AES")
  }

  fun isLockedUri(raw: String): Boolean = raw.trim().startsWith(LOCKED_SCHEME, ignoreCase = true)

  fun encryptServerToLink(server: VpnServer): String {
    val payloadBytes = serializeServerFields(server).toByteArray(StandardCharsets.UTF_8)
    val iv = ByteArray(IV_LENGTH).also { secureRandom.nextBytes(it) }
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, GCMParameterSpec(TAG_BITS, iv))
    cipher.updateAAD(LOCKED_SCHEME.toByteArray(StandardCharsets.US_ASCII))
    val encrypted = cipher.doFinal(payloadBytes)

    val envelope = ByteArray(1 + IV_LENGTH + encrypted.size)
    envelope[0] = VERSION_BYTE
    System.arraycopy(iv, 0, envelope, 1, IV_LENGTH)
    System.arraycopy(encrypted, 0, envelope, 1 + IV_LENGTH, encrypted.size)

    return "$LOCKED_SCHEME${encodeBase64Url(envelope)}"
  }

  fun decryptLinkToServer(rawUri: String, isCustom: Boolean = true): VpnServer? {
    val trimmed = rawUri.trim()
    if (!isLockedUri(trimmed)) return null

    // Ignore optional fragment remark if appended after #
    val token = trimmed.substring(LOCKED_SCHEME.length).substringBefore('#').trim()
    if (token.isEmpty()) return null

    return runCatching {
        val envelope = decodeBase64Url(token) ?: return null
        if (envelope.size <= 1 + IV_LENGTH + 16) return null
        if (envelope[0] != VERSION_BYTE) return null

        val iv = envelope.copyOfRange(1, 1 + IV_LENGTH)
        val ciphertext = envelope.copyOfRange(1 + IV_LENGTH, envelope.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, GCMParameterSpec(TAG_BITS, iv))
        cipher.updateAAD(LOCKED_SCHEME.toByteArray(StandardCharsets.US_ASCII))
        val plainBytes = cipher.doFinal(ciphertext)
        val plainText = String(plainBytes, StandardCharsets.UTF_8)

        deserializeServerFields(plainText, rawLockedUri = trimmed, isCustom = isCustom)
      }
      .getOrNull()
  }

  private fun serializeServerFields(server: VpnServer): String {
    val fields =
      listOf(
        "id" to server.id,
        "name" to server.name,
        "protocol" to server.protocol.name,
        "address" to server.address,
        "port" to server.port.toString(),
        "uuid" to server.uuid,
        "alterId" to server.alterId.toString(),
        "security" to server.security,
        "network" to server.network,
        "tlsMode" to server.tlsMode,
        "sni" to server.sni,
        "host" to server.host,
        "path" to server.path,
        "headerType" to server.headerType,
        "flow" to server.flow,
        "encryption" to server.encryption,
        "fingerprint" to server.fingerprint,
        "alpn" to server.alpn,
        "publicKey" to server.publicKey,
        "shortId" to server.shortId,
        "spiderX" to server.spiderX,
        "serviceName" to server.serviceName,
        "mode" to server.mode,
        "allowInsecure" to server.allowInsecure.toString(),
        "username" to server.username,
        "password" to server.password,
        "payload" to server.payload,
        "sshProxyHost" to server.sshProxyHost,
        "sshProxyPort" to server.sshProxyPort.toString(),
      )
    return fields.joinToString("\n") { (k, v) ->
      "$k:${encodeBase64Url(v.toByteArray(StandardCharsets.UTF_8))}"
    }
  }

  private fun deserializeServerFields(
    plainText: String,
    rawLockedUri: String,
    isCustom: Boolean,
  ): VpnServer? {
    val map = mutableMapOf<String, String>()
    plainText.lines().forEach { line ->
      val idx = line.indexOf(':')
      if (idx > 0) {
        val key = line.substring(0, idx)
        val b64 = line.substring(idx + 1)
        val decoded = decodeBase64Url(b64) ?: return null
        map[key] = String(decoded, StandardCharsets.UTF_8)
      }
    }

    val protocol =
      runCatching { VpnProtocol.valueOf(map["protocol"].orEmpty()) }.getOrNull() ?: return null
    val address = map["address"].orEmpty().trim()
    val port = map["port"]?.toIntOrNull() ?: 0
    if (address.isEmpty() || port !in 1..65535) return null

    val rawId = map["id"].orEmpty().trim()
    val lockedId =
      if (rawId.isNotEmpty()) {
        val digest =
          MessageDigest.getInstance("SHA-256")
            .digest(("LOCKED|$rawId").toByteArray(StandardCharsets.UTF_8))
        digest.take(12).joinToString("") { "%02x".format(it) }
      } else {
        MessageDigest.getInstance("SHA-256")
          .digest(rawLockedUri.toByteArray(StandardCharsets.UTF_8))
          .take(12)
          .joinToString("") { "%02x".format(it) }
      }

    return VpnServer(
      id = lockedId,
      name = map["name"].orEmpty().ifBlank { "${protocol.displayName} Node" },
      protocol = protocol,
      address = address,
      port = port,
      uuid = map["uuid"].orEmpty(),
      alterId = map["alterId"]?.toIntOrNull() ?: 0,
      security = map["security"].orEmpty().ifEmpty { "auto" },
      network = map["network"].orEmpty().ifEmpty { "tcp" },
      tlsMode = map["tlsMode"].orEmpty().ifEmpty { "none" },
      sni = map["sni"].orEmpty(),
      host = map["host"].orEmpty(),
      path = map["path"].orEmpty(),
      headerType = map["headerType"].orEmpty().ifEmpty { "none" },
      flow = map["flow"].orEmpty(),
      encryption = map["encryption"].orEmpty().ifEmpty { "none" },
      fingerprint = map["fingerprint"].orEmpty(),
      alpn = map["alpn"].orEmpty(),
      publicKey = map["publicKey"].orEmpty(),
      shortId = map["shortId"].orEmpty(),
      spiderX = map["spiderX"].orEmpty(),
      serviceName = map["serviceName"].orEmpty(),
      mode = map["mode"].orEmpty(),
      allowInsecure = map["allowInsecure"]?.toBooleanStrictOrNull() ?: false,
      username = map["username"].orEmpty(),
      password = map["password"].orEmpty(),
      payload = map["payload"].orEmpty(),
      sshProxyHost = map["sshProxyHost"].orEmpty(),
      sshProxyPort = map["sshProxyPort"]?.toIntOrNull() ?: 0,
      rawUri = rawLockedUri,
      isCustom = isCustom,
      isLocked = true,
    )
  }

  private const val B64_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

  private fun encodeBase64Url(data: ByteArray): String {
    if (data.isEmpty()) return ""
    val sb = StringBuilder((data.size * 4 + 2) / 3)
    var i = 0
    while (i < data.size) {
      val b0 = data[i].toInt() and 0xFF
      val hasB1 = i + 1 < data.size
      val hasB2 = i + 2 < data.size
      val b1 = if (hasB1) data[i + 1].toInt() and 0xFF else 0
      val b2 = if (hasB2) data[i + 2].toInt() and 0xFF else 0

      sb.append(B64_ALPHABET[b0 ushr 2])
      sb.append(B64_ALPHABET[((b0 and 0x03) shl 4) or (b1 ushr 4)])
      if (hasB1) sb.append(B64_ALPHABET[((b1 and 0x0F) shl 2) or (b2 ushr 6)])
      if (hasB2) sb.append(B64_ALPHABET[b2 and 0x3F])
      i += 3
    }
    return sb.toString()
  }

  private fun decodeBase64Url(text: String): ByteArray? {
    val clean = text.trim().trimEnd('=')
    if (clean.isEmpty()) return ByteArray(0)
    val rem = clean.length % 4
    if (rem == 1) return null

    val outLen = (clean.length * 3) / 4
    val out = ByteArray(outLen)
    var outIdx = 0
    var i = 0
    while (i < clean.length) {
      val c0 = decodeChar(clean[i]) ?: return null
      val c1 = decodeChar(clean[i + 1]) ?: return null
      val hasC2 = i + 2 < clean.length
      val hasC3 = i + 3 < clean.length
      val c2 = if (hasC2) decodeChar(clean[i + 2]) ?: return null else 0
      val c3 = if (hasC3) decodeChar(clean[i + 3]) ?: return null else 0

      out[outIdx++] = ((c0 shl 2) or (c1 ushr 4)).toByte()
      if (hasC2 && outIdx < outLen) {
        out[outIdx++] = (((c1 and 0x0F) shl 4) or (c2 ushr 2)).toByte()
      }
      if (hasC3 && outIdx < outLen) {
        out[outIdx++] = (((c2 and 0x03) shl 6) or c3).toByte()
      }
      i += 4
    }
    return out
  }

  private fun decodeChar(ch: Char): Int? =
    when (ch) {
      in 'A'..'Z' -> ch.code - 'A'.code
      in 'a'..'z' -> ch.code - 'a'.code + 26
      in '0'..'9' -> ch.code - '0'.code + 52
      '-', '+' -> 62
      '_', '/' -> 63
      else -> null
    }
}
