-keep class app.xio.mobile.** { *; }
-keep class go.** { *; }
-keep class org.amnezia.awg.** { *; }
-keep class net.openvpn.** { *; }
-keepclasseswithmembernames,includedescriptorclasses class * { native <methods>; }
-keep class app.xio.openvpn.** { *; }
# Compile-time nullness annotations only, not runtime JNI classes.
-dontwarn javax.annotation.Nonnull
-dontwarn javax.annotation.meta.TypeQualifierDefault
