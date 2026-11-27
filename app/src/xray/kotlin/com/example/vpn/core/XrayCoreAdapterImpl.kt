package com.example.vpn.core

import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.Libv2ray

object XrayCoreAdapterImpl : XrayCoreAdapter {

  private var controller: CoreController? = null
  private var envInitialized = false

  override val isCoreAvailable: Boolean = true

  override val isRunning: Boolean
    get() = controller?.isRunning == true

  @Synchronized
  override fun initCoreEnv(assetDirPath: String) {
    if (!envInitialized) {
      Libv2ray.initCoreEnv(assetDirPath, "")
      envInitialized = true
    }
  }

  @Synchronized
  override fun start(configJson: String, tunFd: Int, events: XrayCoreEvents): Result<Unit> {
    return runCatching {
      val callback =
        object : CoreCallbackHandler {
          override fun startup(): Long {
            events.onCoreStarted()
            return 0L
          }

          override fun shutdown(): Long {
            events.onCoreStopped()
            return 0L
          }

          override fun onEmitStatus(p0: Long, p1: String?): Long {
            if (!p1.isNullOrBlank()) {
              events.onCoreLog(p0, p1)
            }
            return 0L
          }
        }
      val instance = Libv2ray.newCoreController(callback)
      controller = instance
      instance.startLoop(configJson, tunFd)
    }
  }

  @Synchronized
  override fun stop(): Result<Unit> {
    return runCatching {
      controller?.let {
        if (it.isRunning) {
          it.stopLoop()
        }
      }
      controller = null
    }
  }

  override fun measureDelay(testUrl: String): Long? {
    val active = controller ?: return null
    if (!active.isRunning) return null
    return runCatching { active.measureDelay(testUrl) }.getOrNull()?.takeIf { it > 0L }
  }

  override fun measureOutboundDelay(configJson: String, testUrl: String): Long? {
    return runCatching { Libv2ray.measureOutboundDelay(configJson, testUrl) }
      .getOrNull()
      ?.takeIf { it > 0L }
  }

  override fun queryTrafficDelta(): Pair<Long, Long> {
    val active = controller ?: return 0L to 0L
    if (!active.isRunning) return 0L to 0L
    val raw = runCatching { active.queryAllOutboundTrafficStats() }.getOrNull().orEmpty()
    if (raw.isBlank()) return 0L to 0L
    var uplink = 0L
    var downlink = 0L
    raw.split(";").forEach { entry ->
      val parts = entry.split(",")
      if (parts.size == 3 && parts[0] == "proxy") {
        val bytes = parts[2].toLongOrNull() ?: 0L
        when (parts[1]) {
          "uplink" -> uplink += bytes
          "downlink" -> downlink += bytes
        }
      }
    }
    return uplink to downlink
  }
}
