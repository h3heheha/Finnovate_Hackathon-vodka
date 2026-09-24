plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.fraudlens.shield"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.fraudlens.shield"
        minSdk = 26          // Android 8.0; call screening needs Android 10+
        targetSdk = 35
        versionCode = 2
        versionName = "2.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Signed with the debug key so the release APK installs straight away for the demo.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

// Only built-in Android classes are used, so no extra libraries are needed.
