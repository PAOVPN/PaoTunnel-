#include <jni.h>
#include <cstddef>
#include <cstdint>

namespace {

// Key segments are stored XOR-masked and bit-rotated across disjoint tables
// so plaintext key bytes never appear in static binary analysis.
constexpr uint8_t kSegA[8] = {0x60, 0xE8, 0x26, 0xD1, 0x17, 0xE6, 0x80, 0xE2};
constexpr uint8_t kSegB[8] = {0x09, 0xCE, 0xB2, 0xA5, 0xF8, 0x95, 0x80, 0x65};
constexpr uint8_t kSegC[8] = {0x9B, 0x1F, 0xD7, 0x14, 0x1A, 0xFF, 0xC9, 0x54};
constexpr uint8_t kSegD[8] = {0xA4, 0x22, 0x9A, 0xBB, 0xD2, 0xA3, 0x7A, 0x90};

constexpr uint8_t kMaskPrime[8] = {0xA7, 0x3C, 0x5E, 0x91, 0xD2, 0x48, 0x19, 0xF4};
constexpr uint8_t kMaskMix[8] = {0x6B, 0xE3, 0x0D, 0x7A, 0x85, 0x24, 0xC6, 0x52};

uint8_t readSegmentByte(size_t index) {
  switch (index >> 3) {
    case 0:
      return kSegA[index & 7u];
    case 1:
      return kSegB[index & 7u];
    case 2:
      return kSegC[index & 7u];
    default:
      return kSegD[index & 7u];
  }
}

void secureZero(void* ptr, size_t len) {
  volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
  while (len--) {
    *p++ = 0;
  }
}

}  // namespace

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_vpn_crypto_NativeVault_getVaultKey(JNIEnv* env, jobject /* thiz */) {
  constexpr size_t kKeyLen = 32;
  uint8_t keyBuf[kKeyLen];

  for (size_t i = 0; i < kKeyLen; ++i) {
    const uint8_t encoded = readSegmentByte(i);
    const uint8_t unmasked = static_cast<uint8_t>(
        encoded ^ kMaskPrime[i % 8u] ^ kMaskMix[(i * 3u + 5u) % 8u] ^
        static_cast<uint8_t>(i * 29u + 17u));
    keyBuf[i] = static_cast<uint8_t>((unmasked >> 3u) | (unmasked << 5u));
  }

  jbyteArray result = env->NewByteArray(static_cast<jsize>(kKeyLen));
  if (result != nullptr) {
    env->SetByteArrayRegion(
        result, 0, static_cast<jsize>(kKeyLen), reinterpret_cast<const jbyte*>(keyBuf));
  }
  secureZero(keyBuf, kKeyLen);
  return result;
}
