@REM pacman -S mingw-w64-x86_64-cmake
@REM pacman -S mingw-w64-x86_64-make
@REM pacman -S mingw-w64-x86_64-gcc

:: Set up the Android SDK
set ANDROID_SDK=C:/Program Files/Unity 2022.3.62f1/Editor/Data/PlaybackEngines/AndroidPlayer/SDK

:: # Set up the Android NDK
set ANDROID_NDK=C:/Program Files/Unity 2022.3.62f1/Editor/Data/PlaybackEngines/AndroidPlayer/NDK

set JAVA_HOME=C:/Program Files/Unity 2022.3.62f1/Editor/Data/PlaybackEngines/AndroidPlayer/OpenJDK
set Java_JAR_EXECUTABLE=%JAVA_HOME%/bin/javaw.exe

set Path=%JAVA_HOME%/bin;%Path%;

set BUILD_PATH=build-android
@REM sys2 cmake  有问题可以用 git sys 环境调用 win 的 cmake 
cmake -B %BUILD_PATH% -DBUILD_ANDROID=On -DANDROID_ABI=armeabi-v7a -G "MinGW Makefiles" 
cd %BUILD_PATH%
C:/msys64/mingw64/bin/mingw32-make -j20
cd ..

set BUILD_PATH=build-android64
cmake -B %BUILD_PATH% -DBUILD_ANDROID=On -DANDROID_ABI=arm64-v8a -G "MinGW Makefiles" 
cd %BUILD_PATH%
C:/msys64/mingw64/bin/mingw32-make -j20
