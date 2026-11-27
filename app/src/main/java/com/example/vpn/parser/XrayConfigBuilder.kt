package com.example.vpn.parser

import com.example.vpn.model.VpnProtocol
import com.example.vpn.model.VpnServer
import org.json.JSONArray
import org.json.JSONObject

object XrayConfigBuilder {

  fun buildConfig(server: VpnServer, enableTunInbound: Boolean = true): String {
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

    val mappedDomain = resolvePlainVlessMappedDomain(server)
    root.put(
      "dns",
      JSONObject().apply {
        if (mappedDomain != null) {
          put("hosts", JSONObject().put(mappedDomain, server.address.trim()))
        }
        put("servers", JSONArray().put("1.1.1.1").put("8.8.8.8"))
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
    root.put("inbounds", inbounds)

    val outbounds = JSONArray()
    outbounds.put(buildProxyOutbound(server))
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

  private fun isPlainVless(server: VpnServer): Boolean {
    if (server.protocol != VpnProtocol.VLESS) return false
    val securityMode = server.tlsMode.trim().lowercase()
    return securityMode != "tls" && securityMode != "reality"
  }

  private fun resolvePlainVlessMappedDomain(server: VpnServer): String? {
    val cleanAddress = server.address.trim()
    return if (isPlainVless(server) && isIpv4Address(cleanAddress)) {
      "$cleanAddress.sslip.io"
    } else {
      null
    }
  }

  private fun resolveVlessOutboundAddress(server: VpnServer): String {
    return resolvePlainVlessMappedDomain(server) ?: server.address.trim()
  }

  private fun buildProxyOutbound(server: VpnServer): JSONObject {
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
      }
    }

    outbound.put("streamSettings", buildStreamSettings(server))
    outbound.put("mux", JSONObject().put("enabled", false))
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

    when (net) {
      "ws" -> {
        val headers = JSONObject()
        val hostHeader = server.host.ifBlank { server.sni }
        if (hostHeader.isNotBlank()) headers.put("Host", hostHeader)
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
            val hostHeader = server.host.ifBlank { server.sni }
            if (hostHeader.isNotBlank()) put("host", hostHeader)
          },
        )
      }
      "xhttp" -> {
        stream.put(
          "xhttpSettings",
          JSONObject().apply {
            put("path", server.path.ifBlank { "/" })
            val hostHeader = server.host.ifBlank { server.sni }
            if (hostHeader.isNotBlank()) put("host", hostHeader)
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
            val hostHeader = server.host.ifBlank { server.sni }
            if (hostHeader.isNotBlank()) {
              put("host", JSONArray().put(hostHeader))
            }
          },
        )
      }
      else -> {
        if (server.headerType.equals("http", ignoreCase = true)) {
          val headers = JSONObject()
          val hostHeader = server.host.ifBlank { server.sni }
          if (hostHeader.isNotBlank()) {
            headers.put("Host", JSONArray().put(hostHeader))
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
