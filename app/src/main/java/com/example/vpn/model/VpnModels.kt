package com.example.vpn.model

import androidx.compose.runtime.Immutable

enum class VpnProtocol(val displayName: String) {
  VLESS("VLESS"),
  VMESS("VMess"),
  SSH("SSH"),
}

enum class VpnConnectionState {
  DISCONNECTED,
  CONNECTING,
  CONNECTED,
  DISCONNECTING,
  ERROR,
}

@Immutable
data class VpnServer(
  val id: String,
  val name: String,
  val protocol: VpnProtocol,
  val address: String,
  val port: Int,
  val uuid: String = "",
  val alterId: Int = 0,
  val security: String = "auto",
  val network: String = "tcp",
  val tlsMode: String = "none",
  val sni: String = "",
  val host: String = "",
  val path: String = "",
  val headerType: String = "none",
  val flow: String = "",
  val encryption: String = "none",
  val fingerprint: String = "",
  val alpn: String = "",
  val publicKey: String = "",
  val shortId: String = "",
  val spiderX: String = "",
  val serviceName: String = "",
  val mode: String = "",
  val allowInsecure: Boolean = false,
  val username: String = "",
  val password: String = "",
  val payload: String = "",
  val sshProxyHost: String = "",
  val sshProxyPort: Int = 0,
  val rawUri: String = "",
  val isCustom: Boolean = false,
  val latencyMs: Long? = null,
) {
  val sshProxyDisplay: String
    get() = if (sshProxyHost.isNotBlank() && sshProxyPort > 0) "$sshProxyHost:$sshProxyPort" else ""

  val transportSummary: String
    get() {
      if (protocol == VpnProtocol.SSH) {
        val hasProxy = sshProxyHost.isNotBlank() && sshProxyPort > 0
        val hasPayload = payload.isNotBlank()
        val modeLabel =
          when {
            hasProxy && hasPayload -> "PROXY · PAYLOAD"
            hasProxy -> "HTTP PROXY"
            hasPayload -> "PAYLOAD"
            else -> "DIRECT"
          }
        val userPrefix = if (username.isNotBlank()) "$username · " else ""
        return "${userPrefix}$modeLabel"
      }
      val netLabel = network.uppercase()
      val secLabel =
        when (tlsMode.lowercase()) {
          "reality" -> "REALITY"
          "tls" -> "TLS"
          else -> "PLAIN"
        }
      return "$netLabel · $secLabel"
    }
}

@Immutable
data class TrafficStats(
  val uplinkBytes: Long = 0L,
  val downlinkBytes: Long = 0L,
  val uplinkSpeedBps: Long = 0L,
  val downlinkSpeedBps: Long = 0L,
)

@Immutable
data class VpnRuntimeState(
  val connectionState: VpnConnectionState = VpnConnectionState.DISCONNECTED,
  val activeServerId: String? = null,
  val activeServerName: String? = null,
  val connectedAtElapsedMs: Long? = null,
  val trafficStats: TrafficStats = TrafficStats(),
  val errorMessage: String? = null,
  val coreAvailable: Boolean = true,
)
