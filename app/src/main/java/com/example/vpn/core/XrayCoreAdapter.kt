package com.example.vpn.core

interface XrayCoreEvents {
  fun onCoreStarted()

  fun onCoreStopped()

  fun onCoreLog(code: Long, message: String)
}

interface XrayCoreAdapter {
  val isCoreAvailable: Boolean

  val isRunning: Boolean

  fun initCoreEnv(assetDirPath: String)

  fun start(configJson: String, tunFd: Int, events: XrayCoreEvents): Result<Unit>

  fun stop(): Result<Unit>

  fun measureDelay(testUrl: String = "https://www.gstatic.com/generate_204"): Long?

  fun measureOutboundDelay(
    configJson: String,
    testUrl: String = "https://www.gstatic.com/generate_204",
  ): Long?

  fun queryTrafficDelta(): Pair<Long, Long>
}
