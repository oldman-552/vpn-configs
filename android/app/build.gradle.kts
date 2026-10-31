plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.bahrain.vpnconfigs"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.bahrain.vpnconfigs"
        minSdk = 29
        // ECDSA P-256 SPKI public key (base64) that verifies top500.manifest.json.sig.
        // Empty = transition mode (unsigned manifests accepted). Set via gradle property or env.
        val top500Pub = (project.findProperty("top500PublicKeyB64") as String?)
            ?: System.getenv("TOP500_PUBLIC_KEY_B64") ?: ""
        buildConfigField("String", "TOP500_PUBLIC_KEY_B64", "\"${top500Pub.trim()}\"")
        targetSdk = 35
        versionCode = 2
        versionName = "2.0"
    }

    // إنتاج APK مستقل خفيف لكل معمارية (arm64-v8a بحجم ~50% أقل) + نسخة شاملة للتوافق الكامل
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "x86_64")
            isUniversalApk = true
        }
    }

    signingConfigs {
        val ksPath = System.getenv("KEYSTORE_PATH")
        if (!ksPath.isNullOrBlank() && file(ksPath).exists()) {
            create("release") {
                storeFile = file(ksPath)
                storePassword = System.getenv("KEYSTORE_PASSWORD") ?: ""
                keyAlias = System.getenv("KEY_ALIAS") ?: ""
                keyPassword = System.getenv("KEY_PASSWORD") ?: ""
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            // توقيع النسخة النهائية بمفتاح الإصدار إن توفّر، وإلا بمفتاح التطوير لتكون قابلة للتثبيت مباشرة
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }

    composeCompiler {
        includeSourceInformation = false
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
        }
    }

    lint {
        disable += "ExpiredTargetSdkVersion"
        abortOnError = false
    }

    // ضروري جدًا: استخراج المكتبات الأصلية وعدم تجريد رموز Go في libsingbox.so
    packaging {
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += "**/*.so"
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/META-INF/*.kotlin_module"
            excludes += "DebugProbesKt.bin"
        }
    }
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar", "*.jar"))))
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")
    implementation("androidx.work:work-runtime-ktx:2.12.0")

    val composeBom = platform("androidx.compose:compose-bom:2026.09.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    testImplementation("junit:junit:4.13.2")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("org.robolectric:robolectric:4.13")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        moduleName.set("bahrain_vpn_app")
        freeCompilerArgs.add("-Xno-source-debug-extension")
    }
}
