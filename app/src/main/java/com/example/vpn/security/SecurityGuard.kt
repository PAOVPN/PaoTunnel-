package com.example.vpn.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.annotation.Keep
import java.io.File

@Keep
enum class ThreatType {
  PACKET_SNIFFER,
  ROOTED_DEVICE,
}

@Keep
data class SecurityThreat(
  val type: ThreatType,
  val title: String,
  val message: String,
  val details: List<String> = emptyList(),
)

/**
 * Runtime integrity guard that blocks VPN connections when packet capture / sniffing tools
 * or root binaries/managers are detected on the device.
 */
object SecurityGuard {

  val SNIFFER_PACKAGES: Map<String, String> =
    linkedMapOf(
      "com.guoshi.httpcanary" to "HttpCanary",
      "com.emanuelef.remote_capture" to "PCAPdroid",
      "app.greyshirts.sslcapture" to "Packet Capture",
      "com.minhui.networkcapture" to "Network Capture",
    )

  private val ROOT_PACKAGES: Map<String, String> =
    linkedMapOf(
      "com.topjohnwu.magisk" to "Magisk",
      "eu.chainfire.supersu" to "SuperSU",
      "com.koushikdutta.superuser" to "Superuser",
      "com.noshufou.android.su" to "Superuser (SU)",
      "com.thirdparty.superuser" to "Superuser",
      "me.weishu.kernelsu" to "KernelSU",
    )

  private val SU_BINARY_PATHS =
    listOf(
      "/system/bin/su",
      "/system/xbin/su",
      "/sbin/su",
      "/system/sd/xbin/su",
      "/system/bin/failsafe/su",
      "/data/local/xbin/su",
      "/data/local/bin/su",
      "/data/local/su",
      "/su/bin/su",
      "/magisk/.core/bin/su",
    )

  fun inspectDevice(context: Context): SecurityThreat? {
    val pm = context.packageManager
    val detectedSniffers = findInstalledPackages(pm, SNIFFER_PACKAGES)
    if (detectedSniffers.isNotEmpty()) {
      return SecurityThreat(
        type = ThreatType.PACKET_SNIFFER,
        title = "Security Warning",
        message = "Security Warning: Packet Sniffer detected!",
        details = detectedSniffers,
      )
    }

    val rootIndicators = detectRootIndicators(pm)
    if (rootIndicators.isNotEmpty()) {
      return SecurityThreat(
        type = ThreatType.ROOTED_DEVICE,
        title = "Security Warning",
        message = "Security Warning: Rooted device detected! VPN connection is blocked.",
        details = rootIndicators,
      )
    }

    return null
  }

  private fun findInstalledPackages(
    pm: PackageManager,
    candidates: Map<String, String>,
  ): List<String> {
    val found = mutableListOf<String>()
    for ((pkg, label) in candidates) {
      if (isPackageInstalled(pm, pkg)) {
        found.add("$label ($pkg)")
      }
    }
    return found
  }

  private fun isPackageInstalled(pm: PackageManager, packageName: String): Boolean {
    return runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
          pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0L))
        } else {
          @Suppress("DEPRECATION")
          pm.getPackageInfo(packageName, 0)
        }
        true
      }
      .getOrDefault(false)
  }

  private fun detectRootIndicators(pm: PackageManager): List<String> {
    val findings = mutableListOf<String>()
    findings.addAll(findInstalledPackages(pm, ROOT_PACKAGES))

    for (path in SU_BINARY_PATHS) {
      val exists = runCatching { File(path).exists() }.getOrDefault(false)
      if (exists) {
        findings.add("su binary ($path)")
        break
      }
    }

    val tags = Build.TAGS.orEmpty()
    if (tags.contains("test-keys", ignoreCase = true) && !isLikelyEmulator()) {
      findings.add("Unofficial build tags (test-keys)")
    }

    return findings
  }

  private fun isLikelyEmulator(): Boolean {
    val fp = Build.FINGERPRINT.orEmpty()
    val model = Build.MODEL.orEmpty()
    val product = Build.PRODUCT.orEmpty()
    val hardware = Build.HARDWARE.orEmpty()
    return fp.startsWith("generic", ignoreCase = true) ||
      fp.startsWith("unknown", ignoreCase = true) ||
      fp.contains("emulator", ignoreCase = true) ||
      model.contains("Emulator", ignoreCase = true) ||
      model.contains("Android SDK built for", ignoreCase = true) ||
      product.contains("sdk_gphone", ignoreCase = true) ||
      hardware.contains("goldfish", ignoreCase = true) ||
      hardware.contains("ranchu", ignoreCase = true)
  }
}
