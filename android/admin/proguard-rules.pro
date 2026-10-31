# =====================================================================
# R8 Tree-Shaking + Resource Shrinking for Admin APK v1
# Strips ~30 MB of unused material-icons-extended & AndroidX classes
# while keeping app classes intact for JUnit/Robolectric & stack traces.
# =====================================================================
-dontobfuscate
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

-keep class com.bahrain.vpnadmin.** { *; }
-dontwarn sun.misc.**
-dontwarn java.lang.instrument.**
