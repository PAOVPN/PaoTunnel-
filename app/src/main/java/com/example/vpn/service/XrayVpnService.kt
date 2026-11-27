package com.example.vpn.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.vpn.core.XrayCoreAdapterImpl
import com.example.vpn.core.XrayCoreEvents
import com.example.vpn.model.VpnServer
import com.example.vpn.parser.VpnLinkParser
import com.example.vpn.parser.XrayConfigBuilder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class XrayVpnService : VpnService() {

  companion object {
    const val ACTION_CONNECT = "com.example.vpn.ACTION_CONNECT"
    const val ACTION_DISCONNECT = "com.example.vpn.ACTION_DISCONNECT"
    const val EXTRA_SERVER_JSON = "extra_server_json"

    private const val CHANNEL_ID = "pao_tunnel_vpn_channel"
    private const val NOTIFICATION_ID = 1001

    fun startVpn(context: Context, server: VpnServer) {
      val intent =
        Intent(context, XrayVpnService::class.java).apply {
          action = ACTION_CONNECT
          putExtra(EXTRA_SERVER_JSON, VpnLinkParser.toStorageJson(listOf(server)))
        }
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        context.startForegroundService(intent)
      } else {
        context.startService(intent)
      }
    }

    fun stopVpn(context: Context) {
      val intent =
        Intent(context, XrayVpnService::class.java).apply { action = ACTION_DISCONNECT }
      context.startService(intent)
    }
  }

  private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private var vpnInterface: ParcelFileDescriptor? = null
  private var statsJob: Job? = null
  private var coreJob: Job? = null

  override fun onCreate() {
    super.onCreate()
    createNotificationChannel()
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_DISCONNECT -> {
        disconnectAndStop()
        return START_NOT_STICKY
      }
      ACTION_CONNECT -> {
        val rawJson = intent.getStringExtra(EXTRA_SERVER_JSON).orEmpty()
        val server = VpnLinkParser.fromStorageJson(rawJson).firstOrNull()
        if (server == null) {
          VpnStateHolder.setDisconnected("Invalid server configuration.")
          stopSelf()
          return START_NOT_STICKY
        }
        startForegroundNotification(server.name, connecting = true)
        connectServer(server)
        return START_STICKY
      }
      else -> return START_NOT_STICKY
    }
  }

  private fun connectServer(server: VpnServer) {
    coreJob?.cancel()
    statsJob?.cancel()

    VpnStateHolder.setConnecting(server.id, server.name)

    coreJob =
      serviceScope.launch {
        runCatching {
            XrayCoreAdapterImpl.stop()
            runCatching { vpnInterface?.close() }
            vpnInterface = null

            if (!XrayCoreAdapterImpl.isCoreAvailable) {
              error(
                "Xray Core (libv2ray.aar) is not bundled in this local preview build. Build the APK via GitHub Actions to include AndroidLibXrayLite."
              )
            }

            XrayCoreAdapterImpl.initCoreEnv(filesDir.absolutePath)

            val tunPfd =
              Builder()
                .setSession(server.name)
                .setMtu(1500)
                .addAddress("172.19.0.1", 30)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .apply {
                  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    setMetered(false)
                  }
                  runCatching { addDisallowedApplication(packageName) }
                }
                .establish()
                ?: error("Failed to establish Android VPN interface.")

            vpnInterface = tunPfd
            val configJson = XrayConfigBuilder.buildConfig(server, enableTunInbound = true)

            val result =
              XrayCoreAdapterImpl.start(
                configJson = configJson,
                tunFd = tunPfd.fd,
                events =
                  object : XrayCoreEvents {
                    override fun onCoreStarted() {
                      VpnStateHolder.setConnected(
                        serverId = server.id,
                        serverName = server.name,
                        connectedAtElapsedMs = SystemClock.elapsedRealtime(),
                      )
                      startForegroundNotification(server.name, connecting = false)
                      startTrafficPolling()
                    }

                    override fun onCoreStopped() {
                      statsJob?.cancel()
                    }

                    override fun onCoreLog(code: Long, message: String) = Unit
                  },
              )

            result.getOrThrow()

            // Ensure connected state is reflected if startLoop returns synchronously
            if (XrayCoreAdapterImpl.isRunning &&
              VpnStateHolder.state.value.connectionState !=
                com.example.vpn.model.VpnConnectionState.CONNECTED
            ) {
              VpnStateHolder.setConnected(
                serverId = server.id,
                serverName = server.name,
                connectedAtElapsedMs = SystemClock.elapsedRealtime(),
              )
              startForegroundNotification(server.name, connecting = false)
              startTrafficPolling()
            }
          }
          .onFailure { error ->
            runCatching { vpnInterface?.close() }
            vpnInterface = null
            XrayCoreAdapterImpl.stop()
            VpnStateHolder.setDisconnected(error.message ?: "Failed to start Xray VPN.")
            stopForegroundCompat()
            stopSelf()
          }
      }
  }

  private fun startTrafficPolling() {
    statsJob?.cancel()
    statsJob =
      serviceScope.launch {
        while (isActive && XrayCoreAdapterImpl.isRunning) {
          val (up, down) = XrayCoreAdapterImpl.queryTrafficDelta()
          VpnStateHolder.updateTrafficStats(up, down)
          delay(1000L)
        }
      }
  }

  private fun disconnectAndStop() {
    VpnStateHolder.setDisconnecting()
    statsJob?.cancel()
    coreJob?.cancel()
    serviceScope.launch {
      XrayCoreAdapterImpl.stop()
      runCatching { vpnInterface?.close() }
      vpnInterface = null
      VpnStateHolder.setDisconnected(null)
      stopForegroundCompat()
      stopSelf()
    }
  }

  override fun onRevoke() {
    disconnectAndStop()
    super.onRevoke()
  }

  override fun onDestroy() {
    statsJob?.cancel()
    coreJob?.cancel()
    XrayCoreAdapterImpl.stop()
    runCatching { vpnInterface?.close() }
    vpnInterface = null
    serviceScope.cancel()
    super.onDestroy()
  }

  private fun createNotificationChannel() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val manager = getSystemService(NotificationManager::class.java)
      val channel =
        NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
          )
          .apply {
            description = getString(R.string.vpn_notification_channel_desc)
            setShowBadge(false)
          }
      manager.createNotificationChannel(channel)
    }
  }

  private fun startForegroundNotification(serverName: String, connecting: Boolean) {
    val notification = buildNotification(serverName, connecting)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      startForeground(
        NOTIFICATION_ID,
        notification,
        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
      )
    } else {
      startForeground(NOTIFICATION_ID, notification)
    }
  }

  private fun buildNotification(serverName: String, connecting: Boolean): Notification {
    val openIntent =
      PendingIntent.getActivity(
        this,
        0,
        Intent(this, MainActivity::class.java).apply {
          flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        },
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
      )

    val disconnectIntent =
      PendingIntent.getService(
        this,
        1,
        Intent(this, XrayVpnService::class.java).apply { action = ACTION_DISCONNECT },
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
      )

    val title =
      if (connecting) "Connecting to $serverName…" else "PAO Tunnel · $serverName"
    val content =
      if (connecting) "Initializing Xray Core TUN interface" else "Traffic protected via Xray Core"

    return NotificationCompat.Builder(this, CHANNEL_ID)
      .setSmallIcon(R.mipmap.ic_launcher)
      .setContentTitle(title)
      .setContentText(content)
      .setOngoing(true)
      .setOnlyAlertOnce(true)
      .setContentIntent(openIntent)
      .addAction(
        android.R.drawable.ic_menu_close_clear_cancel,
        getString(R.string.vpn_notification_disconnect),
        disconnectIntent,
      )
      .build()
  }

  private fun stopForegroundCompat() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      stopForeground(STOP_FOREGROUND_REMOVE)
    } else {
      @Suppress("DEPRECATION") stopForeground(true)
    }
  }
}
