
# Previously, you should have set up an Android toolchain, e.g.
# ~/android-ndk-r7b/build/tools/make-standalone-toolchain.sh --platform=android-9 --install-dir=$HOME/android-ndk-r7b/standalone-toolchain-api9

ANDROID_NDK_PATH=$HOME/android-ndk-r9c
ANDROID_PLATFORM=19
ANDROID_ARCH=arm
ANDROID_TOOLCHAIN=arm-linux-androideabi-4.8

case $(uname -m) in
*i[3456]86*)
BITS=x86
 ;;
*x86_64*)
BITS=x86_64
 ;;
*)
echo Couldn\'t determine bitness of kernel.
exit 1
esac

case $(uname) in

# ---- Linux
*Linux*)
ANDROID_BUILD_PLATFORM=linux-$BITS
GCC_BUILD_PLATFORM=i686-pc-linux-gnu
 ;;

*Darwin*)
# ---- Darwin
ANDROID_BUILD_PLATFORM=darwin-$BITS
GCC_BUILD_PLATFORM=i686-apple-darwin11
 ;;

*MINGW*)
ANDROID_BUILD_PLATFORM=windows
GCC_BUILD_PLATFORM=i386-pc-mingw32
 ;;

*)
echo Unknown platform
exit 1
 ;;

esac

ANDROID_NDK_TOOLCHAIN=$ANDROID_NDK_PATH/toolchains/$ANDROID_TOOLCHAIN/prebuilt/$ANDROID_BUILD_PLATFORM
ANDROID_NDK_PLATFORM=$ANDROID_NDK_PATH/platforms/android-$ANDROID_PLATFORM/arch-$ANDROID_ARCH
ANDROID_NDK_HOST=$ANDROID_ARCH-linux-androideabi

# Sanity checks before getting into configure/make
if ! [ -x $ANDROID_NDK_TOOLCHAIN/bin/$ANDROID_NDK_HOST-gcc ]; then
  echo "C compiler not found,"
  echo '  '$ANDROID_NDK_TOOLCHAIN/bin/$ANDROID_NDK_HOST-gcc
  exit 1
fi

if ! [ -x $ANDROID_NDK_TOOLCHAIN/bin/$ANDROID_NDK_HOST-g++ ]; then
  echo "C++ compiler not found,"
  echo '  '$ANDROID_NDK_TOOLCHAIN/bin/$ANDROID_NDK_HOST-g++
  exit 1
fi

if ! $ANDROID_NDK_TOOLCHAIN/bin/$ANDROID_NDK_HOST-gcc -v 2>/dev/null; then
  echo "C compiler would not run,"
  echo '  '$ANDROID_NDK_TOOLCHAIN/bin/$ANDROID_NDK_HOST-gcc
  exit 1
fi

if ! $ANDROID_NDK_TOOLCHAIN/bin/$ANDROID_NDK_HOST-g++ -v 2>/dev/null; then
  echo "C compiler would not run,"
  echo '  '$ANDROID_NDK_TOOLCHAIN/bin/$ANDROID_NDK_HOST-g++
  exit 1
fi

# Also, if you get errors about an unrecognized configuration, you
# need a recent version of config.sub and config.guess, available at:
# http://git.savannah.gnu.org/gitweb/?p=config.git;a=tree

fixconfigsubguess() {
    cd ..
    if ! test -e configure; then
        NOCONFIGURE=true ./autogen.sh
    fi
    rm config.sub
    rm config.guess
    if curl -V; then
      curl >config.sub 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub;hb=HEAD'
      curl >config.guess 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD'
    elif wget -V; then
      wget -O config.sub 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub;hb=HEAD'
      wget -O config.guess 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD'
    else
      echo Error: Need curl or wget to get config.sub and config.guess
      exit 1
    fi
    cd build
}

# Check for some known-bad config.sub/config.guess files
# and replace them if found.
# (These were found in MingW autoconf 2.68)
checkconfigsubguess() {
if (echo "513a0fb7db33b8a0c5ba5345fc70ff62 *../config.sub" \
	| md5sum --status -c -) \
|| (echo "513a0fb7db33b8a0c5ba5345fc70ff62 *../config.guess" \
	| md5sum --status -c -);
then
    fixconfigsubguess
fi
}

# Uncomment the following line to do the above automatically.  It is
# not enabled by default because the correct files will be distributed
# with the tarball.
#fixconfigsubguess
checkconfigsubguess

mkdir -p android
cd android

PATH=$ANDROID_NDK_TOOLCHAIN/bin:$PATH

../../configure \
  --host=$ANDROID_NDK_HOST \
  --build=$GCC_BUILD_PLATFORM \
  CC="$ANDROID_NDK_HOST-gcc --sysroot=$ANDROID_NDK_PLATFORM" \
  CXX="$ANDROID_NDK_HOST-g++ --sysroot=$ANDROID_NDK_PLATFORM"

make
