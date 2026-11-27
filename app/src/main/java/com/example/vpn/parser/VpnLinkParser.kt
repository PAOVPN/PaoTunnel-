package com.example.vpn.parser

import android.util.Base64
import com.example.vpn.crypto.ConfigCrypto
import com.example.vpn.model.VpnProtocol
import com.example.vpn.model.VpnServer
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject

object VpnLinkParser {

  fun parseServersPayload(payload: String): List<VpnServer> {
    val trimmed = payload.trim()
    if (trimmed.isEmpty()) return emptyList()

    // 1. Try JSON Array or JSON Object
    if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
      val jsonParsed = parseJsonServers(trimmed)
      if (jsonParsed.isNotEmpty()) {
        return jsonParsed.distinctBy { it.id }
      }
    }

    // 2. Try plain lines of vless:// / vmess://
    val directLines = parseUriLines(trimmed)
    if (directLines.isNotEmpty()) {
      return directLines.distinctBy { it.id }
    }

    // 3. Try Base64-decoded subscription lines
    val decoded = decodeBase64Flexible(trimmed)
    if (decoded != null) {
      if (decoded.trim().startsWith("[") || decoded.trim().startsWith("{")) {
        val decodedJson = parseJsonServers(decoded.trim())
        if (decodedJson.isNotEmpty()) return decodedJson.distinctBy { it.id }
      }
      val decodedLines = parseUriLines(decoded)
      if (decodedLines.isNotEmpty()) return decodedLines.distinctBy { it.id }
    }

    return emptyList()
  }

  private fun parseJsonServers(jsonText: String): List<VpnServer> {
    return runCatching {
        val results = mutableListOf<VpnServer>()
        if (jsonText.startsWith("[")) {
          val array = JSONArray(jsonText)
          for (i in 0 until array.length()) {
            parseJsonArrayItem(array.opt(i))?.let { results.add(it) }
          }
        } else if (jsonText.startsWith("{")) {
          val root = JSONObject(jsonText)
          val arrayKeys =
            listOf(
              "servers",
              "data",
              "list",
              "nodes",
              "configs",
              "items",
              "results",
              "ssh",
              "v2ray",
              "links",
              "proxies",
            )
          var handled = false
          for (key in arrayKeys) {
            val arr = root.optJSONArray(key)
            if (arr != null) {
              handled = true
              for (i in 0 until arr.length()) {
                parseJsonArrayItem(arr.opt(i))?.let { results.add(it) }
              }
            }
          }
          if (!handled) {
            // Check if root itself is a single server object
            parseJsonObjectServer(root)?.let { results.add(it) }
          }
        }
        results
      }
      .getOrDefault(emptyList())
  }

  private fun parseJsonArrayItem(item: Any?): VpnServer? {
    return when (item) {
      is String -> parseUri(item, isCustom = false)
      is JSONObject -> parseJsonObjectServer(item)
      else -> null
    }
  }

  private fun parseJsonObjectServer(obj: JSONObject): VpnServer? {
    val overrideName =
      firstNonBlank(
        obj.optString("name"),
        obj.optString("remarks"),
        obj.optString("ps"),
        obj.optString("title"),
        obj.optString("label"),
        obj.optString("serverName"),
      )

    // Case A: Object wraps a share link under url/link/config/uri/vless/vmess/ssh/node
    val linkCandidate =
      listOf(
          obj.optString("url"),
          obj.optString("link"),
          obj.optString("uri"),
          obj.optString("config"),
          obj.optString("shareLink"),
          obj.optString("vless"),
          obj.optString("vmess"),
          obj.optString("ssh"),
          obj.optString("node"),
        )
        .map { it.trim() }
        .firstOrNull { candidate ->
          candidate.isNotEmpty() &&
            candidate != "null" &&
            (candidate.startsWith("vless://", ignoreCase = true) ||
              candidate.startsWith("vmess://", ignoreCase = true) ||
              candidate.startsWith("ssh://", ignoreCase = true) ||
              candidate.startsWith(ConfigCrypto.LOCKED_SCHEME, ignoreCase = true))
        }
        .orEmpty()
    if (linkCandidate.isNotEmpty()) {
      val parsed = parseUri(linkCandidate, isCustom = false)
      if (parsed != null) {
        val flag = obj.optString("flag").trim()
        val finalName =
          when {
            overrideName.isNotEmpty() && flag.isNotEmpty() && !overrideName.contains(flag) ->
              "$flag $overrideName"
            overrideName.isNotEmpty() -> overrideName
            else -> parsed.name
          }
        return parsed.copy(name = finalName)
      }
    }

    // Case B: Structured fields directly in JSON object
    val protocolStr =
      firstNonBlank(obj.optString("protocol"), obj.optString("type")).lowercase()
    val protocol =
      when (protocolStr) {
        "vless" -> VpnProtocol.VLESS
        "vmess" -> VpnProtocol.VMESS
        "ssh" -> VpnProtocol.SSH
        else -> return null
      }

    if (protocol == VpnProtocol.SSH) {
      val host =
        firstNonBlank(
          obj.optString("host"),
          obj.optString("address"),
          obj.optString("add"),
          obj.optString("ip"),
          obj.optString("server"),
        )
      val port = obj.optInt("port", obj.optString("port").toIntOrNull() ?: 22)
      val username = firstNonBlank(obj.optString("username"), obj.optString("user"))
      val password = firstNonBlank(obj.optString("password"), obj.optString("pass"))
      val rawPayload = obj.optString("payload").trim().let { if (it == "null") "" else decodeBase64PayloadSafely(it) }
      val proxyString =
        firstNonBlank(obj.optString("proxy"), obj.optString("httpProxy"), obj.optString("remoteProxy"))
      val (proxyHost, proxyPort) = parseProxyHostPort(proxyString, obj.optString("proxyHost"), obj.optInt("proxyPort", 0))
      if (host.isEmpty() || port <= 0 || username.isEmpty()) return null
      val flag = obj.optString("flag").trim()
      val displayName =
        when {
          overrideName.isNotEmpty() && flag.isNotEmpty() && !overrideName.contains(flag) ->
            "$flag $overrideName"
          overrideName.isNotEmpty() -> overrideName
          else -> "SSH · $host:$port"
        }
      return createSshServer(
        name = displayName,
        host = host,
        port = port,
        username = username,
        password = password,
        payload = rawPayload,
        sshProxyHost = proxyHost,
        sshProxyPort = proxyPort,
        isCustom = false,
      )
    }

    val address =
      firstNonBlank(
        obj.optString("address"),
        obj.optString("add"),
        obj.optString("host"),
        obj.optString("ip"),
        obj.optString("server"),
      )
    val port = obj.optInt("port", obj.optString("port").toIntOrNull() ?: 0)
    val uuid = firstNonBlank(obj.optString("id"), obj.optString("uuid"))
    if (address.isEmpty() || port <= 0 || uuid.isEmpty()) return null

    val network =
      firstNonBlank(obj.optString("network"), obj.optString("net"), obj.optString("transport"))
        .ifEmpty { "tcp" }
        .lowercase()
    val tlsRaw =
      firstNonBlank(obj.optString("security"), obj.optString("tls"))
        .ifEmpty { if (obj.optBoolean("tls", false)) "tls" else "none" }
        .lowercase()
    val tlsMode =
      when {
        tlsRaw == "reality" -> "reality"
        tlsRaw == "tls" || tlsRaw == "true" -> "tls"
        else -> "none"
      }
    val sni = firstNonBlank(obj.optString("sni"), obj.optString("peer"))
    val hostHeader = firstNonBlank(obj.optString("hostHeader"), obj.optString("wsHost"), obj.optString("host"))
    val path = obj.optString("path").trim()
    val flow = obj.optString("flow").trim()
    val encryption = obj.optString("encryption").trim().ifEmpty { "none" }
    val security = obj.optString("scy").trim().ifEmpty { "auto" }
    val alterId = obj.optInt("aid", 0)
    val fp = firstNonBlank(obj.optString("fp"), obj.optString("fingerprint"))
    val pbk = firstNonBlank(obj.optString("pbk"), obj.optString("publicKey"))
    val sid = firstNonBlank(obj.optString("sid"), obj.optString("shortId"))
    val spx = firstNonBlank(obj.optString("spx"), obj.optString("spiderX"))
    val alpn = obj.optString("alpn").trim()
    val serviceName = obj.optString("serviceName").trim()
    val flag = obj.optString("flag").trim()

    val displayName =
      when {
        overrideName.isNotEmpty() && flag.isNotEmpty() && !overrideName.contains(flag) ->
          "$flag $overrideName"
        overrideName.isNotEmpty() -> overrideName
        else -> "$address:$port"
      }

    val stableId = stableId("${protocol.name}|$address|$port|$uuid|$network|$tlsMode|$path|$sni")
    return VpnServer(
      id = stableId,
      name = displayName,
      protocol = protocol,
      address = address,
      port = port,
      uuid = uuid,
      alterId = alterId,
      security = security,
      network = network,
      tlsMode = tlsMode,
      sni = sni,
      host = hostHeader,
      path = path,
      flow = flow,
      encryption = encryption,
      fingerprint = fp,
      alpn = alpn,
      publicKey = pbk,
      shortId = sid,
      spiderX = spx,
      serviceName = serviceName,
      allowInsecure = obj.optBoolean("allowInsecure", false),
      rawUri = obj.toString(),
      isCustom = false,
    )
  }

  private fun parseUriLines(text: String): List<VpnServer> {
    return text
      .lines()
      .mapNotNull { line ->
        val cleaned = line.trim()
        if (cleaned.startsWith("vless://", ignoreCase = true) ||
          cleaned.startsWith("vmess://", ignoreCase = true) ||
          cleaned.startsWith("ssh://", ignoreCase = true) ||
          cleaned.startsWith(ConfigCrypto.LOCKED_SCHEME, ignoreCase = true)
        ) {
          parseUri(cleaned, isCustom = false)
        } else {
          null
        }
      }
  }

  fun parseUri(uri: String, isCustom: Boolean = true): VpnServer? {
    val trimmed = uri.trim()
    return when {
      trimmed.startsWith(ConfigCrypto.LOCKED_SCHEME, ignoreCase = true) ->
        ConfigCrypto.decryptLinkToServer(trimmed, isCustom = isCustom)
      trimmed.startsWith("vless://", ignoreCase = true) -> parseVless(trimmed, isCustom)
      trimmed.startsWith("vmess://", ignoreCase = true) -> parseVmess(trimmed, isCustom)
      trimmed.startsWith("ssh://", ignoreCase = true) -> parseSsh(trimmed, isCustom)
      else -> null
    }
  }

  fun createSshServer(
    name: String,
    host: String,
    port: Int,
    username: String,
    password: String,
    payload: String,
    sshProxyHost: String = "",
    sshProxyPort: Int = 0,
    isCustom: Boolean = true,
  ): VpnServer {
    val cleanHost = host.trim()
    val cleanUser = username.trim()
    val cleanPayload = payload.trim()
    val cleanProxyHost = sshProxyHost.trim()
    val cleanProxyPort = if (cleanProxyHost.isNotEmpty() && sshProxyPort in 1..65535) sshProxyPort else 0
    val displayName = name.trim().ifBlank { "SSH · $cleanHost:$port" }
    val id = stableId("SSH|$cleanHost|$port|$cleanUser|$cleanProxyHost:$cleanProxyPort|$cleanPayload")
    val server =
      VpnServer(
        id = id,
        name = displayName,
        protocol = VpnProtocol.SSH,
        address = cleanHost,
        port = port,
        network = "ssh",
        tlsMode = if (cleanPayload.isNotEmpty()) "payload" else "none",
        username = cleanUser,
        password = password,
        payload = cleanPayload,
        sshProxyHost = cleanProxyHost,
        sshProxyPort = cleanProxyPort,
        isCustom = isCustom,
      )
    return server.copy(rawUri = toSshUri(server))
  }

  fun toSshUri(server: VpnServer): String {
    val userPart = urlEncode(server.username)
    val passPart = urlEncode(server.password)
    val hostPart =
      if (server.address.contains(":") && !server.address.startsWith("[")) {
        "[${server.address.trim()}]"
      } else {
        server.address.trim()
      }
    val queryParts = mutableListOf<String>()
    if (server.sshProxyHost.isNotBlank() && server.sshProxyPort in 1..65535) {
      val proxyHostPort = "${server.sshProxyHost.trim()}:${server.sshProxyPort}"
      queryParts.add("proxy=${urlEncode(proxyHostPort)}")
    }
    if (server.payload.isNotBlank()) {
      val encodedPayload =
        Base64.encodeToString(
          server.payload.toByteArray(StandardCharsets.UTF_8),
          Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
      queryParts.add("payload=$encodedPayload")
    }
    val querySuffix = if (queryParts.isNotEmpty()) "?${queryParts.joinToString("&")}" else ""
    val remarkSuffix = if (server.name.isNotBlank()) "#${urlEncode(server.name)}" else ""
    return "ssh://$userPart:$passPart@$hostPart:${server.port}$querySuffix$remarkSuffix"
  }

  fun toShareUri(server: VpnServer, locked: Boolean = false): String {
    if (server.isLocked || locked) {
      return if (server.isLocked && ConfigCrypto.isLockedUri(server.rawUri)) {
        server.rawUri.trim()
      } else {
        ConfigCrypto.encryptServerToLink(server)
      }
    }
    return when (server.protocol) {
      VpnProtocol.SSH -> toSshUri(server)
      VpnProtocol.VLESS ->
        if (server.rawUri.trim().startsWith("vless://", ignoreCase = true)) {
          server.rawUri.trim()
        } else {
          toVlessUri(server)
        }
      VpnProtocol.VMESS ->
        if (server.rawUri.trim().startsWith("vmess://", ignoreCase = true)) {
          server.rawUri.trim()
        } else {
          toVmessUri(server)
        }
    }
  }

  private fun toVlessUri(server: VpnServer): String {
    val hostPart =
      if (server.address.contains(":") && !server.address.startsWith("[")) {
        "[${server.address.trim()}]"
      } else {
        server.address.trim()
      }
    val params = mutableListOf<String>()
    params.add("encryption=${urlEncode(server.encryption.ifBlank { "none" })}")
    params.add("security=${urlEncode(server.tlsMode.ifBlank { "none" })}")
    params.add("type=${urlEncode(server.network.ifBlank { "tcp" })}")
    if (server.sni.isNotBlank()) params.add("sni=${urlEncode(server.sni)}")
    if (server.host.isNotBlank()) params.add("host=${urlEncode(server.host)}")
    if (server.path.isNotBlank()) params.add("path=${urlEncode(server.path)}")
    if (server.flow.isNotBlank()) params.add("flow=${urlEncode(server.flow)}")
    if (server.fingerprint.isNotBlank()) params.add("fp=${urlEncode(server.fingerprint)}")
    if (server.alpn.isNotBlank()) params.add("alpn=${urlEncode(server.alpn)}")
    if (server.publicKey.isNotBlank()) params.add("pbk=${urlEncode(server.publicKey)}")
    if (server.shortId.isNotBlank()) params.add("sid=${urlEncode(server.shortId)}")
    if (server.spiderX.isNotBlank()) params.add("spx=${urlEncode(server.spiderX)}")
    if (server.serviceName.isNotBlank()) params.add("serviceName=${urlEncode(server.serviceName)}")
    if (server.allowInsecure) params.add("allowInsecure=1")
    val remark = if (server.name.isNotBlank()) "#${urlEncode(server.name)}" else ""
    return "vless://${urlEncode(server.uuid)}@$hostPart:${server.port}?${params.joinToString("&")}$remark"
  }

  private fun toVmessUri(server: VpnServer): String {
    val json =
      JSONObject().apply {
        put("v", "2")
        put("ps", server.name)
        put("add", server.address)
        put("port", server.port.toString())
        put("id", server.uuid)
        put("aid", server.alterId.toString())
        put("scy", server.security)
        put("net", server.network)
        put("type", server.headerType)
        put("host", server.host)
        put("path", if (server.network == "grpc" && server.serviceName.isNotBlank()) server.serviceName else server.path)
        put("tls", if (server.tlsMode == "tls" || server.tlsMode == "reality") server.tlsMode else "")
        if (server.sni.isNotBlank()) put("sni", server.sni)
        if (server.alpn.isNotBlank()) put("alpn", server.alpn)
        if (server.fingerprint.isNotBlank()) put("fp", server.fingerprint)
        if (server.allowInsecure) put("allowInsecure", "1")
      }
    val encoded =
      Base64.encodeToString(json.toString().toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
    return "vmess://$encoded"
  }

  fun parseProxyString(rawProxy: String): Pair<String, Int>? {
    val cleaned = rawProxy.trim()
    if (cleaned.isEmpty()) return null
    val withoutScheme =
      cleaned.removePrefix("http://").removePrefix("https://").trimEnd('/')
    parseHostPort(withoutScheme)?.let { (h, p) ->
      if (h.isNotBlank() && p in 1..65535) return h.trim() to p
    }
    if (!withoutScheme.contains(":") && withoutScheme.isNotBlank()) {
      return withoutScheme to 8080
    }
    return null
  }

  private fun parseProxyHostPort(
    proxyString: String,
    explicitHost: String,
    explicitPort: Int,
  ): Pair<String, Int> {
    parseProxyString(proxyString)?.let { return it }
    val cleanHost = explicitHost.trim().let { if (it == "null") "" else it }
    return if (cleanHost.isNotEmpty() && explicitPort in 1..65535) {
      cleanHost to explicitPort
    } else if (cleanHost.isNotEmpty()) {
      cleanHost to 8080
    } else {
      "" to 0
    }
  }

  private fun parseSsh(uri: String, isCustom: Boolean): VpnServer? {
    val body = uri.substring("ssh://".length)
    val fragmentSplit = body.split("#", limit = 2)
    val beforeFragment = fragmentSplit[0]
    val rawRemark = if (fragmentSplit.size > 1) urlDecode(fragmentSplit[1]) else ""

    val querySplit = beforeFragment.split("?", limit = 2)
    val authority = querySplit[0]
    val queryStr = if (querySplit.size > 1) querySplit[1] else ""
    val params = parseQueryParams(queryStr)

    val atIndex = authority.lastIndexOf('@')
    if (atIndex <= 0) return null
    val credentials = authority.substring(0, atIndex)
    val hostPort = authority.substring(atIndex + 1).trim()
    val colonIdx = credentials.indexOf(':')
    val username =
      if (colonIdx >= 0) urlDecode(credentials.substring(0, colonIdx)).trim()
      else urlDecode(credentials).trim()
    val password =
      if (colonIdx >= 0) urlDecode(credentials.substring(colonIdx + 1)) else ""

    val (host, port) =
      parseHostPort(hostPort)
        ?: run {
          if (hostPort.isNotBlank() && !hostPort.contains(":")) hostPort to 22 else return null
        }
    if (username.isEmpty() || host.isEmpty() || port <= 0) return null

    val rawProxyParam = params["proxy"] ?: params["httpProxy"] ?: ""
    val (proxyHost, proxyPort) = parseProxyHostPort(rawProxyParam, "", 0)
    val rawPayloadParam = params["payload"].orEmpty()
    val decodedPayload = decodeBase64PayloadSafely(rawPayloadParam)

    val server =
      createSshServer(
        name = rawRemark,
        host = host,
        port = port,
        username = username,
        password = password,
        payload = decodedPayload,
        sshProxyHost = proxyHost,
        sshProxyPort = proxyPort,
        isCustom = isCustom,
      )
    return server.copy(rawUri = uri)
  }

  private fun parseVless(uri: String, isCustom: Boolean): VpnServer? {
    val body = uri.substring("vless://".length)
    val fragmentSplit = body.split("#", limit = 2)
    val beforeFragment = fragmentSplit[0]
    val rawRemark = if (fragmentSplit.size > 1) urlDecode(fragmentSplit[1]) else ""

    val querySplit = beforeFragment.split("?", limit = 2)
    val authority = querySplit[0]
    val queryStr = if (querySplit.size > 1) querySplit[1] else ""

    val atIndex = authority.indexOf('@')
    if (atIndex <= 0) return null
    val uuid = urlDecode(authority.substring(0, atIndex)).trim()
    val hostPort = authority.substring(atIndex + 1).trim()
    val (address, port) = parseHostPort(hostPort) ?: return null
    if (uuid.isEmpty() || address.isEmpty() || port <= 0) return null

    val params = parseQueryParams(queryStr)
    val network = params["type"]?.trim()?.lowercase()?.ifEmpty { "tcp" } ?: "tcp"
    val securityMode = params["security"]?.trim()?.lowercase()?.ifEmpty { "none" } ?: "none"
    val sni = params["sni"] ?: params["peer"] ?: ""
    val host = params["host"] ?: ""
    val path = params["path"] ?: ""
    val headerType = params["headerType"] ?: "none"
    val flow = params["flow"] ?: ""
    val encryption = params["encryption"] ?: "none"
    val fp = params["fp"] ?: ""
    val alpn = params["alpn"] ?: ""
    val pbk = params["pbk"] ?: ""
    val sid = params["sid"] ?: ""
    val spx = params["spx"] ?: ""
    val serviceName = params["serviceName"] ?: ""
    val mode = params["mode"] ?: ""
    val allowInsecure = params["allowInsecure"] == "1" || params["allowInsecure"] == "true"

    val remarks = rawRemark.ifBlank { "VLESS · $address:$port" }
    return VpnServer(
      id = stableId("VLESS|$address|$port|$uuid|$network|$securityMode|$path|$sni|$flow"),
      name = remarks,
      protocol = VpnProtocol.VLESS,
      address = address,
      port = port,
      uuid = uuid,
      network = network,
      tlsMode = securityMode,
      sni = sni,
      host = host,
      path = path,
      headerType = headerType,
      flow = flow,
      encryption = encryption,
      fingerprint = fp,
      alpn = alpn,
      publicKey = pbk,
      shortId = sid,
      spiderX = spx,
      serviceName = serviceName,
      mode = mode,
      allowInsecure = allowInsecure,
      rawUri = uri,
      isCustom = isCustom,
    )
  }

  private fun parseVmess(uri: String, isCustom: Boolean): VpnServer? {
    val encoded = uri.substring("vmess://".length).trim()
    val jsonStr = decodeBase64Flexible(encoded) ?: return null
    val json = runCatching { JSONObject(jsonStr) }.getOrNull() ?: return null

    val address = json.optString("add").trim()
    val port = json.optInt("port", json.optString("port").toIntOrNull() ?: 0)
    val uuid = json.optString("id").trim()
    if (address.isEmpty() || port <= 0 || uuid.isEmpty()) return null

    val remarks = json.optString("ps").trim().ifBlank { "VMess · $address:$port" }
    val alterId = json.optInt("aid", json.optString("aid").toIntOrNull() ?: 0)
    val security = json.optString("scy").trim().ifEmpty { "auto" }
    val network = json.optString("net").trim().ifEmpty { "tcp" }.lowercase()
    val headerType = json.optString("type").trim().ifEmpty { "none" }
    val host = json.optString("host").trim()
    val path = json.optString("path").trim()
    val tlsRaw = json.optString("tls").trim().lowercase()
    val tlsMode = if (tlsRaw == "tls" || tlsRaw == "reality") tlsRaw else "none"
    val sni = json.optString("sni").trim()
    val alpn = json.optString("alpn").trim()
    val fp = json.optString("fp").trim()
    val allowInsecure =
      json.optBoolean("allowInsecure", false) || json.optString("allowInsecure") == "1"

    return VpnServer(
      id = stableId("VMESS|$address|$port|$uuid|$network|$tlsMode|$path|$sni"),
      name = remarks,
      protocol = VpnProtocol.VMESS,
      address = address,
      port = port,
      uuid = uuid,
      alterId = alterId,
      security = security,
      network = network,
      tlsMode = tlsMode,
      sni = sni,
      host = host,
      path = path,
      headerType = headerType,
      fingerprint = fp,
      alpn = alpn,
      serviceName = if (network == "grpc") path else "",
      allowInsecure = allowInsecure,
      rawUri = uri,
      isCustom = isCustom,
    )
  }

  private fun parseHostPort(hostPort: String): Pair<String, Int>? {
    return if (hostPort.startsWith("[")) {
      val closeBracket = hostPort.indexOf(']')
      if (closeBracket <= 1) return null
      val host = hostPort.substring(1, closeBracket)
      val portPart = hostPort.substring(closeBracket + 1)
      if (!portPart.startsWith(":")) return null
      val port = portPart.substring(1).toIntOrNull() ?: return null
      host to port
    } else {
      val colon = hostPort.lastIndexOf(':')
      if (colon <= 0) return null
      val host = hostPort.substring(0, colon)
      val port = hostPort.substring(colon + 1).toIntOrNull() ?: return null
      host to port
    }
  }

  private fun parseQueryParams(query: String): Map<String, String> {
    if (query.isBlank()) return emptyMap()
    val map = mutableMapOf<String, String>()
    query.split("&").forEach { pair ->
      val idx = pair.indexOf('=')
      if (idx > 0) {
        val key = urlDecode(pair.substring(0, idx))
        val value = urlDecode(pair.substring(idx + 1))
        map[key] = value
      }
    }
    return map
  }

  private fun urlEncode(value: String): String {
    return runCatching { URLEncoder.encode(value, StandardCharsets.UTF_8.name()).replace("+", "%20") }
      .getOrDefault(value)
  }

  private fun urlDecode(value: String): String {
    return runCatching { URLDecoder.decode(value, StandardCharsets.UTF_8.name()) }
      .getOrDefault(value)
  }

  private fun decodeBase64PayloadSafely(raw: String): String {
    val trimmed = raw.trim()
    if (trimmed.isEmpty()) return ""
    // If already looks like plain-text payload template, keep as-is
    if (trimmed.contains("[crlf]", ignoreCase = true) ||
      trimmed.contains("[host", ignoreCase = true) ||
      trimmed.contains("\n") ||
      trimmed.contains("\r") ||
      trimmed.contains(" ")
    ) {
      return trimmed
    }
    val decoded = decodeBase64Flexible(trimmed) ?: return trimmed
    val looksValidText =
      decoded.isNotEmpty() &&
        decoded.none { ch ->
          ch == '\uFFFD' || (ch.code < 0x20 && ch != '\r' && ch != '\n' && ch != '\t')
        }
    return if (looksValidText) decoded else trimmed
  }

  private fun decodeBase64Flexible(raw: String): String? {
    val sanitized = raw.trim().replace("\n", "").replace("\r", "")
    val flagsList =
      listOf(
        Base64.DEFAULT,
        Base64.URL_SAFE or Base64.NO_WRAP,
        Base64.NO_WRAP or Base64.NO_PADDING,
        Base64.URL_SAFE or Base64.NO_PADDING,
      )
    for (flags in flagsList) {
      val decoded =
        runCatching {
            String(Base64.decode(sanitized, flags), StandardCharsets.UTF_8)
          }
          .getOrNull()
      if (!decoded.isNullOrBlank()) return decoded
    }
    return null
  }

  private fun firstNonBlank(vararg values: String?): String {
    for (v in values) {
      if (!v.isNullOrBlank() && v != "null") return v.trim()
    }
    return ""
  }

  private fun stableId(seed: String): String {
    val bytes = MessageDigest.getInstance("SHA-256").digest(seed.toByteArray(StandardCharsets.UTF_8))
    return bytes.take(12).joinToString("") { "%02x".format(it) }
  }

  fun toStorageJson(servers: List<VpnServer>): String {
    val arr = JSONArray()
    servers.forEach { s ->
      arr.put(
        JSONObject().apply {
          put("id", s.id)
          put("name", s.name)
          put("protocol", s.protocol.name)
          put("address", s.address)
          put("port", s.port)
          put("uuid", s.uuid)
          put("alterId", s.alterId)
          put("security", s.security)
          put("network", s.network)
          put("tlsMode", s.tlsMode)
          put("sni", s.sni)
          put("host", s.host)
          put("path", s.path)
          put("headerType", s.headerType)
          put("flow", s.flow)
          put("encryption", s.encryption)
          put("fingerprint", s.fingerprint)
          put("alpn", s.alpn)
          put("publicKey", s.publicKey)
          put("shortId", s.shortId)
          put("spiderX", s.spiderX)
          put("serviceName", s.serviceName)
          put("mode", s.mode)
          put("allowInsecure", s.allowInsecure)
          put("username", s.username)
          put("password", s.password)
          put("payload", s.payload)
          put("sshProxyHost", s.sshProxyHost)
          put("sshProxyPort", s.sshProxyPort)
          put("rawUri", if (s.isLocked && !ConfigCrypto.isLockedUri(s.rawUri)) "" else s.rawUri)
          put("isCustom", s.isCustom)
          put("isLocked", s.isLocked)
          if (s.latencyMs != null) put("latencyMs", s.latencyMs)
        }
      )
    }
    return arr.toString()
  }

  fun fromStorageJson(raw: String): List<VpnServer> {
    if (raw.isBlank()) return emptyList()
    return runCatching {
        val arr = JSONArray(raw)
        buildList {
          for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val protocol =
              runCatching { VpnProtocol.valueOf(o.optString("protocol")) }
                .getOrNull() ?: continue
            val locked = o.optBoolean("isLocked", false)
            val storedRawUri = o.optString("rawUri", "")
            add(
              VpnServer(
                id = o.optString("id"),
                name = o.optString("name"),
                protocol = protocol,
                address = o.optString("address"),
                port = o.optInt("port"),
                uuid = o.optString("uuid", ""),
                alterId = o.optInt("alterId", 0),
                security = o.optString("security", "auto"),
                network = o.optString("network", "tcp"),
                tlsMode = o.optString("tlsMode", "none").trim().lowercase().ifEmpty { "none" },
                sni = o.optString("sni", ""),
                host = o.optString("host", ""),
                path = o.optString("path", ""),
                headerType = o.optString("headerType", "none"),
                flow = o.optString("flow", ""),
                encryption = o.optString("encryption", "none"),
                fingerprint = o.optString("fingerprint", ""),
                alpn = o.optString("alpn", ""),
                publicKey = o.optString("publicKey", ""),
                shortId = o.optString("shortId", ""),
                spiderX = o.optString("spiderX", ""),
                serviceName = o.optString("serviceName", ""),
                mode = o.optString("mode", ""),
                allowInsecure = o.optBoolean("allowInsecure", false),
                username = o.optString("username", ""),
                password = o.optString("password", ""),
                payload = o.optString("payload", ""),
                sshProxyHost = o.optString("sshProxyHost", ""),
                sshProxyPort = o.optInt("sshProxyPort", 0),
                rawUri = if (locked && !ConfigCrypto.isLockedUri(storedRawUri)) "" else storedRawUri,
                isCustom = o.optBoolean("isCustom", false),
                isLocked = locked,
                latencyMs = if (o.has("latencyMs")) o.optLong("latencyMs") else null,
              )
            )
          }
        }
      }
      .getOrDefault(emptyList())
  }
}
