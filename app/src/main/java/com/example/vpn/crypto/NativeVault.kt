package com.example.vpn.crypto

import androidx.annotation.Keep

/**
 * JNI bridge to `libnative-lib.so` so the AES-256 vault key never resides in Kotlin/Java bytecode.
 */
@Keep
object NativeVault {
  init {
    System.loadLibrary("native-lib")
  }

  @Keep
  external fun getVaultKey(): ByteArray
}
