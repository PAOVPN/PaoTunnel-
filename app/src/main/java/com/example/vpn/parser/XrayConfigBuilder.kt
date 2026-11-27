package com.example.vpn.parser

import com.example.vpn.model.VpnProtocol
import com.example.vpn.model.VpnServer
import org.json.JSONArray
import org.json.JSONObject

object XrayConfigBuilder {

  fun buildConfig(
    server: VpnServer,
    enableTunInbound: Boolean = true,
    sshLocalSocksPort: Int = 10808,
  ): String {
    val root = JSONObject()

    root.put("log", JSONObject().put("loglevel", "warning"))
    root.put("stats", JSONObject())
    root.put(
      "policy",
      JSONObject().apply {
        put(
          "levels",
          JSONObject().put(
            "8",
            JSONObject().apply {
              put("connIdle", 300)
              put("downlinkOnly", 1)
              put("handshake", 4)
              put("uplinkOnly", 1)
            },
          ),
        )
        put(
          "system",
          JSONObject().apply {
            put("statsOutboundUplink", true)
            put("statsOutboundDownlink", true)
          },
        )
      },
    )

    val isSsh = server.protocol == VpnProtocol.SSH
    val mappedDomain = resolvePlainVlessMappedDomain(server)
    root.put(
      "dns",
      JSONObject().apply {
        if (mappedDomain != null) {
          put("hosts", JSONObject().put(mappedDomain, server.address.trim()))
        }
        if (isSsh) {
          // SSH direct-tcpip tunnels TCP only, so force DNS resolution over TCP through SOCKS5
          put("servers", JSONArray().put("tcp://1.1.1.1").put("tcp://8.8.8.8"))
        } else {
          put("servers", JSONArray().put("1.1.1.1").put("8.8.8.8").put("localhost"))
        }
        put("queryStrategy", "UseIPv4")
      },
    )

    val inbounds = JSONArray()
    if (enableTunInbound) {
      inbounds.put(
        JSONObject().apply {
          put("tag", "tun-in")
          put("protocol", "tun")
          put(
            "settings",
            JSONObject().apply {
              put("name", "xray0")
              put("mtu", 1500)
              put("userLevel", 8)
            },
          )
          put(
            "sniffing",
            JSONObject().apply {
              put("enabled", true)
              put("destOverride", JSONArray().put("http").put("tls").put("quic"))
              put("routeOnly", true)
            },
          )
        }
      )
    }
    if (!isSsh) {
      inbounds.put(
        JSONObject().apply {
          put("tag", "socks-in")
          put("listen", "127.0.0.1")
          put("port", 10808)
          put("protocol", "socks")
          put(
            "settings",
            JSONObject().apply {
              put("auth", "noauth")
              put("udp", true)
              put("userLevel", 8)
            },
          )
        }
      )
    }
    root.put("inbounds", inbounds)

    val outbounds = JSONArray()
    outbounds.put(buildProxyOutbound(server, sshLocalSocksPort))
    if (isSsh) {
      outbounds.put(
        JSONObject().apply {
          put("tag", "dns-out")
          put("protocol", "dns")
        }
      )
    }
    outbounds.put(
      JSONObject().apply {
        put("tag", "direct")
        put("protocol", "freedom")
        put("settings", JSONObject().put("domainStrategy", "UseIP"))
      }
    )
    outbounds.put(
      JSONObject().apply {
        put("tag", "block")
        put("protocol", "blackhole")
      }
    )
    root.put("outbounds", outbounds)

    root.put(
      "routing",
      JSONObject().apply {
        put("domainStrategy", "IPIfNonMatch")
        put(
          "rules",
          JSONArray().apply {
            if (isSsh) {
              put(
                JSONObject().apply {
                  put("type", "field")
                  put("inboundTag", JSONArray().put("tun-in"))
                  put("port", 53)
                  put("outboundTag", "dns-out")
                }
              )
            }
            put(
              JSONObject().apply {
                put("type", "field")
                put(
                  "ip",
                  JSONArray()
                    .put("10.0.0.0/8")
                    .put("172.16.0.0/12")
                    .put("192.168.0.0/16")
                    .put("127.0.0.0/8"),
                )
                put("outboundTag", "direct")
              }
            )
          },
        )
      },
    )

    return root.toString(2)
  }

  private val ipv4Regex = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")

  private fun isIpv4Address(address: String): Boolean {
    val match = ipv4Regex.matchEntire(address.trim()) ?: return false
    return (1..4).all { index ->
      val octet = match.groupValues[index].toIntOrNull() ?: return@all false
      octet in 0..255
    }
  }

  private fun isPrivateOrLocalAddress(address: String): Boolean {
    val clean = address.trim().trimEnd('.').lowercase()
    if (clean.isEmpty()) return true
    if (clean == "localhost" ||
      clean.endsWith(".localhost") ||
      clean.endsWith(".local") ||
      clean.endsWith(".internal") ||
      clean.endsWith(".lan") ||
      clean.endsWith(".home.arpa")
    ) {
      return true
    }
    if (isIpv4Address(clean)) {
      val parts = clean.split(".").mapNotNull { it.toIntOrNull() }
      if (parts.size == 4) {
        val a = parts[0]
        val b = parts[1]
        return a == 10 ||
          a == 127 ||
          (a == 172 && b in 16..31) ||
          (a == 192 && b == 168) ||
          (a == 169 && b == 254)
      }
    }
    val unbracketed = clean.removePrefix("[").removeSuffix("]")
    if (unbracketed == "::1" || unbracketed.startsWith("fc") || unbracketed.startsWith("fd") || unbracketed.startsWith("fe80:")) {
      return true
    }
    return false
  }

  private fun isPlainVless(server: VpnServer): Boolean {
    if (server.protocol != VpnProtocol.VLESS) return false
    val securityMode = server.tlsMode.trim().lowercase()
    return securityMode != "tls" && securityMode != "reality"
  }

  private fun resolvePlainVlessMappedDomain(server: VpnServer): String? {
    val cleanAddress = server.address.trim()
    if (!isPlainVless(server) || isPrivateOrLocalAddress(cleanAddress)) return null
    val sanitized =
      cleanAddress
        .lowercase()
        .replace(Regex("[^a-z0-9-]"), "-")
        .replace(Regex("-+"), "-")
        .trim('-')
        .ifEmpty { "pao-node" }
    return "$sanitized.local"
  }

  private fun resolveVlessOutboundAddress(server: VpnServer): String {
    return resolvePlainVlessMappedDomain(server) ?: server.address.trim()
  }

  private fun buildProxyOutbound(server: VpnServer, sshLocalSocksPort: Int): JSONObject {
    val outbound = JSONObject()
    outbound.put("tag", "proxy")

    when (server.protocol) {
      VpnProtocol.VLESS -> {
        outbound.put("protocol", "vless")
        val user =
          JSONObject().apply {
            put("id", server.uuid)
            put("encryption", server.encryption.ifBlank { "none" })
            put("level", 8)
            if (server.flow.isNotBlank()) put("flow", server.flow)
          }
        val vnext =
          JSONObject().apply {
            put("address", resolveVlessOutboundAddress(server))
            put("port", server.port)
            put("users", JSONArray().put(user))
          }
        outbound.put("settings", JSONObject().put("vnext", JSONArray().put(vnext)))
        outbound.put("streamSettings", buildStreamSettings(server))
        outbound.put("mux", JSONObject().put("enabled", false))
      }
      VpnProtocol.VMESS -> {
        outbound.put("protocol", "vmess")
        val user =
          JSONObject().apply {
            put("id", server.uuid)
            put("alterId", server.alterId)
            put("security", server.security.ifBlank { "auto" })
            put("level", 8)
          }
        val vnext =
          JSONObject().apply {
            put("address", server.address)
            put("port", server.port)
            put("users", JSONArray().put(user))
          }
        outbound.put("settings", JSONObject().put("vnext", JSONArray().put(vnext)))
        outbound.put("streamSettings", buildStreamSettings(server))
        outbound.put("mux", JSONObject().put("enabled", false))
      }
      VpnProtocol.SSH -> {
        outbound.put("protocol", "socks")
        val socksServer =
          JSONObject().apply {
            put("address", "127.0.0.1")
            put("port", sshLocalSocksPort)
          }
        outbound.put("settings", JSONObject().put("servers", JSONArray().put(socksServer)))
      }
    }

    return outbound
  }

  private fun buildStreamSettings(server: VpnServer): JSONObject {
    val stream = JSONObject()
    val net = server.network.lowercase().ifBlank { "tcp" }
    stream.put("network", net)

    val tlsMode = server.tlsMode.trim().lowercase()
    stream.put("security", if (tlsMode == "tls" || tlsMode == "reality") tlsMode else "none")
    if (resolvePlainVlessMappedDomain(server) != null) {
      stream.put("sockopt", JSONObject().put("domainStrategy", "UseIP"))
    }

    if (tlsMode == "tls") {
      val sni = server.sni.ifBlank { server.host.ifBlank { server.address } }
      stream.put(
        "tlsSettings",
        JSONObject().apply {
          put("serverName", sni)
          if (server.fingerprint.isNotBlank()) put("fingerprint", server.fingerprint)
          if (server.alpn.isNotBlank()) {
            val alpnArr = JSONArray()
            server.alpn.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach {
              alpnArr.put(it)
            }
            if (alpnArr.length() > 0) put("alpn", alpnArr)
          }
        },
      )
    } else if (tlsMode == "reality") {
      val sni = server.sni.ifBlank { server.address }
      stream.put(
        "realitySettings",
        JSONObject().apply {
          put("serverName", sni)
          put("fingerprint", server.fingerprint.ifBlank { "chrome" })
          put("publicKey", server.publicKey)
          put("shortId", server.shortId)
          if (server.spiderX.isNotBlank()) put("spiderX", server.spiderX)
        },
      )
    }

    val mappedPlainVless = resolvePlainVlessMappedDomain(server) != null
    val effectiveHostHeader =
      server.host.ifBlank { server.sni }.ifBlank {
        if (mappedPlainVless) server.address.trim() else ""
      }

    when (net) {
      "ws" -> {
        val headers = JSONObject()
        if (effectiveHostHeader.isNotBlank()) headers.put("Host", effectiveHostHeader)
        stream.put(
          "wsSettings",
          JSONObject().apply {
            put("path", server.path.ifBlank { "/" })
            if (headers.length() > 0) put("headers", headers)
          },
        )
      }
      "grpc" -> {
        stream.put(
          "grpcSettings",
          JSONObject().apply {
            put("serviceName", server.serviceName.ifBlank { server.path })
            put("multiMode", server.mode.equals("multi", ignoreCase = true))
          },
        )
      }
      "httpupgrade" -> {
        stream.put(
          "httpupgradeSettings",
          JSONObject().apply {
            put("path", server.path.ifBlank { "/" })
            if (effectiveHostHeader.isNotBlank()) put("host", effectiveHostHeader)
          },
        )
      }
      "xhttp" -> {
        stream.put(
          "xhttpSettings",
          JSONObject().apply {
            put("path", server.path.ifBlank { "/" })
            if (effectiveHostHeader.isNotBlank()) put("host", effectiveHostHeader)
            if (server.mode.isNotBlank()) put("mode", server.mode)
          },
        )
      }
      "h2",
      "http" -> {
        stream.put(
          "httpSettings",
          JSONObject().apply {
            put("path", server.path.ifBlank { "/" })
            if (effectiveHostHeader.isNotBlank()) {
              put("host", JSONArray().put(effectiveHostHeader))
            }
          },
        )
      }
      else -> {
        if (server.headerType.equals("http", ignoreCase = true)) {
          val headers = JSONObject()
          if (effectiveHostHeader.isNotBlank()) {
            headers.put("Host", JSONArray().put(effectiveHostHeader))
          }
          stream.put(
            "tcpSettings",
            JSONObject().apply {
              put(
                "header",
                JSONObject().apply {
                  put("type", "http")
                  put(
                    "request",
                    JSONObject().apply {
                      put("path", JSONArray().put(server.path.ifBlank { "/" }))
                      if (headers.length() > 0) put("headers", headers)
                    },
                  )
                },
              )
            },
          )
        }
      }
    }

    return stream
  }
}
