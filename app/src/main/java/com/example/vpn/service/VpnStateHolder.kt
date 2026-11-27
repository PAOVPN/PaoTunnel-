package com.example.vpn.service

import com.example.vpn.core.XrayCoreAdapterImpl
import com.example.vpn.model.TrafficStats
import com.example.vpn.model.VpnConnectionState
import com.example.vpn.model.VpnRuntimeState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

object VpnStateHolder {
  private val _state =
    MutableStateFlow(VpnRuntimeState(coreAvailable = XrayCoreAdapterImpl.isCoreAvailable))
  val state: StateFlow<VpnRuntimeState> = _state.asStateFlow()

  fun setConnecting(serverId: String, serverName: String) {
    _state.update {
      it.copy(
        connectionState = VpnConnectionState.CONNECTING,
        activeServerId = serverId,
        activeServerName = serverName,
        connectedAtElapsedMs = null,
        trafficStats = TrafficStats(),
        errorMessage = null,
      )
    }
  }

  fun setConnected(serverId: String, serverName: String, connectedAtElapsedMs: Long) {
    _state.update {
      it.copy(
        connectionState = VpnConnectionState.CONNECTED,
        activeServerId = serverId,
        activeServerName = serverName,
        connectedAtElapsedMs = connectedAtElapsedMs,
        errorMessage = null,
      )
    }
  }

  fun setDisconnecting() {
    _state.update { it.copy(connectionState = VpnConnectionState.DISCONNECTING) }
  }

  fun setDisconnected(errorMessage: String? = null) {
    _state.update {
      it.copy(
        connectionState =
          if (errorMessage != null) VpnConnectionState.ERROR else VpnConnectionState.DISCONNECTED,
        activeServerId = if (errorMessage != null) it.activeServerId else null,
        connectedAtElapsedMs = null,
        trafficStats = TrafficStats(),
        errorMessage = errorMessage,
      )
    }
  }

  fun updateTrafficStats(uplinkDelta: Long, downlinkDelta: Long) {
    _state.update { current ->
      val prev = current.trafficStats
      current.copy(
        trafficStats =
          TrafficStats(
            uplinkBytes = prev.uplinkBytes + uplinkDelta,
            downlinkBytes = prev.downlinkBytes + downlinkDelta,
            uplinkSpeedBps = uplinkDelta,
            downlinkSpeedBps = downlinkDelta,
          )
      )
    }
  }

  fun clearError() {
    _state.update {
      it.copy(
        connectionState =
          if (it.connectionState == VpnConnectionState.ERROR) {
            VpnConnectionState.DISCONNECTED
          } else {
            it.connectionState
          },
        errorMessage = null,
      )
    }
  }
}
