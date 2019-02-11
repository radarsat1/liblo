

Building liblo for other platforms
==================================

This document describes how to build liblo for platforms that require
special configuration.

Building liblo for Microsoft Visual Studio
------------------------------------------

Some Windows users prefer to use Microsoft Visual Studio to the
well-supported MSYS2 environment.

For them, an alternative configuration system is supported by liblo
using the excellent `CMake` utility.
The `cmake` folder contains a file called `CMakeLists.txt`.
To use it, you must first install CMake either through your favorite
package manager (such as MSYS2's pacman, or Chocolatey, NuGet, etc),
or by going to,

    http://cmake.org

Once CMake has been installed, you can run it as a GUI program, or run
it from the command-line specifying the "generator" as your version of
Visual Studio, and adding `Win64` if you want a 64-bit build.  Note
that you must run it from the `cmake` folder, NOT the project's main
directory:

    > cd liblo\cmake
    > C:\<path to>\cmake.exe -G "Visual Studio 15 2017 Win64"

You can specify some options such as enable/disalbing the C++ tests,
examples, tests, static library build, and command-line tools.  You
can also choose to enable or disable the `lo_server_thread` interface
via the `THREADING` option.  On Windows, the Win32 threading API is
used, therefore there is no longer a need to install the `pthreads`
library on Windows.

Building liblo for Android
--------------------------

The `build` directory contains a script called `android_build.sh`.
Ensure that the variables at the top of the script conform to where
you have installed the Android NDK, and to the platform you wish to
target.

The default values are:

    ANDROID_NDK_PATH=$HOME/android-ndk-r9c
    ANDROID_PLATFORM=19
    ANDROID_ARCH=arm
    ANDROID_TOOLCHAIN=arm-linux-androideabi-4.8

Then, run the script from the `build` directory:

    $ ./android_build.sh

The script will run `configure` in a cross-compilation mode.
It will only work if you have not previously run `configure` in the
liblo directory.

If the script gives an error, examine `build/android/config.log`.
Otherwise, it should successfully create an ARM binary file in the
directory `build/android/src/.libs`.
