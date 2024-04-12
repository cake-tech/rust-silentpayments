default: build build-emulator build-android

build:
    cargo build

build-emulator:
    cargo ndk -t x86 -o ../android/app/src/main/jniLibs build

build-android:
    cargo ndk -o ../android/app/src/main/jniLibs build
