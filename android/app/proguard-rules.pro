# =====================================================================
# R8 Tree-Shaking + Resource Shrinking Rules for bahrain-vpn v3.1
# Strips unused Material Icons (~25-30 MB DEX) & unused AndroidX classes
# while keeping JNI bridges, WorkManager, and app classes 100% intact.
# =====================================================================
-dontobfuscate
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# JNI C/Go tunnel bridges (critical: native code resolves exact class/method names)
-keep class hev.htproxy.** { *; }
-keep class io.nekohasekai.** { *; }
-keep class libbox.** { *; }
-keep class go.** { *; }

# Keep app classes & public APIs intact for Robolectric unit tests & Repo isolation audit
-keep class com.bahrain.vpnconfigs.** { *; }

# WorkManager background workers
-keep class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

-dontwarn sun.misc.**
-dontwarn java.lang.instrument.**
