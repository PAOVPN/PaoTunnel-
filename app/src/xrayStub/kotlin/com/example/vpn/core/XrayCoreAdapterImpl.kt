package com.example.vpn.core

object XrayCoreAdapterImpl : XrayCoreAdapter {

  override val isCoreAvailable: Boolean = false

  override val isRunning: Boolean = false

  override fun initCoreEnv(assetDirPath: String) = Unit

  override fun start(configJson: String, tunFd: Int, events: XrayCoreEvents): Result<Unit> {
    return Result.failure(
      IllegalStateException(
        "Xray native library (app/libs/libv2ray.aar) is not bundled in this preview build. Build via GitHub Actions to embed AndroidLibXrayLite."
      )
    )
  }

  override fun stop(): Result<Unit> = Result.success(Unit)

  override fun measureDelay(testUrl: String): Long? = null

  override fun measureOutboundDelay(configJson: String, testUrl: String): Long? = null

  override fun queryTrafficDelta(): Pair<Long, Long> = 0L to 0L
}
