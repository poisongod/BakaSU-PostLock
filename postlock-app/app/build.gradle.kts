plugins {
    id("com.android.application") version "9.4.1"
}

android {
    namespace = "org.postlock.boot"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.postlock.boot"
        minSdk = 26
        targetSdk = 33
        versionCode = 5
        versionName = "1.4"
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
