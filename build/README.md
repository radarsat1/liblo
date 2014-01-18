

Building liblo for other platforms
==================================

This document describes how to build liblo for platforms that require
special configuration.

Building liblo for Microsoft Visual Studio
------------------------------------------

Some Windows users prefer to use Microsoft Visual Studio to the
well-supported MSYS/MingW or Cygwin environments.

For them, an alternative configuration system is supported by liblo
using the excellent `premake4` utility.
The `build` folder contains a file called `premake4.lua`.
It must be accompanied by `premake4.exe`, which can be downloaded
from:

    http://industriousone.com/premake/download

Once `premake4.exe` is copied to the `build` directory, open a
`cmd.exe` prompt and `cd` to the `build` directory.
Then, run `premake4` with arguments specifying the version of
Microsoft Visual Studio you wish to use.
For example, for MSVS 2010:

    > premake4 vs2010

You may provide the `--without-threads` option if you wish to exclude
support for liblo's `lo_server_thread` API, which can be helpful if you
have not downloaded the Win32 port of `pthread`.
This can be found at,

    http://sourceware.org/pthreads-win32/

You should specify the location of this library using the `--pthreads`
option to premake4, e.g.:

    > premake4 --pthreads=C:/Libraries/pthreads-w32-2-9-1-release vs2010

Unfortunately liblo does not yet support the Win32 thread API, so
pthreads-w32 is required for lo_server_thread functionality. Note that
test programs (`subtest.exe`, `testlo.exe`) will not be built without
threading enabled.

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
