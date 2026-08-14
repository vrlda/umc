plugins {
    kotlin("jvm") version "2.0.21"
}

group = "org.universalmesh"
version = "0.2.3"

repositories { mavenCentral() }

kotlin { jvmToolchain(17) }
