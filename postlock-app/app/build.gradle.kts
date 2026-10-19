plugins {
    id("com.android.application") version "9.4.1"
}

android {
    namespace = "com.postlock.boot"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.postlock.boot"
        minSdk = 26
        targetSdk = 33
        versionCode = 8
        versionName = "1.7"
    }

    signingConfigs {
        create("fixed") {
            storeFile = file("../postlock-debug.keystore")
            storePassword = "postlock"
            keyAlias = "postlock"
            keyPassword = "postlock"
        }
    }

    buildTypes {
        debug { signingConfig = signingConfigs.getByName("fixed") }
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("fixed")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
