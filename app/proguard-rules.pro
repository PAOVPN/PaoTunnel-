# PAO Tunnel R8 / ProGuard Configuration

-keepattributes Signature,InnerClasses,EnclosingMethod,*Annotation*
-keepclassmembers class * {
    @androidx.annotation.Keep *;
}
-keep @androidx.annotation.Keep class * { *; }

# Native JNI bridge for AES-256 vault key
-keep class com.example.vpn.crypto.NativeVault { *; }
-keepclassmembers class com.example.vpn.crypto.NativeVault {
    native <methods>;
}
-keepclassmembers class * {
    native <methods>;
}

# Xray Core (AndroidLibXrayLite / gomobile JNI callbacks)
-keep class libv2ray.** { *; }
-keep class go.** { *; }
-dontwarn libv2ray.**
-dontwarn go.**
-keep class com.example.vpn.core.** { *; }
-keep class com.example.vpn.service.XrayVpnService { *; }

# JSch SSH Tunnel (reflective Cipher, KEX, Signature, Compression classes)
-keep class com.jcraft.jsch.** { *; }
-dontwarn com.jcraft.jsch.**
-dontwarn org.ietf.jgss.**
-dontwarn java.awt.**
-dontwarn javax.swing.**
-keep class com.example.vpn.ssh.** { *; }

# SlowDNS & Security Guard & Models
-keep class com.example.vpn.security.** { *; }
-keep class com.example.vpn.model.** { *; }

# Gson keep rules (including reflective serialization)
-keep class com.google.gson.** { *; }
-dontwarn com.google.gson.**
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# OkHttp / Okio / Conscrypt / BouncyCastle
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
-dontwarn javax.annotation.**
-dontwarn sun.misc.Unsafe

# Kotlin Coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-dontwarn kotlinx.coroutines.flow.**
