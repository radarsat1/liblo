
# Previously, you should have set up an Android toolchain, e.g.
# ~/android-ndk-r7b/build/tools/make-standalone-toolchain.sh --platform=android-9 --install-dir=$HOME/android-ndk-r7b/standalone-toolchain-api9

ANDROID_NDK_PATH=$HOME/android-ndk-r7b
ANDROID_PLATFORM=9
ANDROID_NDK_STANDALONE_TOOLCHAIN=$ANDROID_NDK_PATH/standalone-toolchain-api$ANDROID_PLATFORM

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
    wget -O config.sub 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub;hb=HEAD'
    wget -O config.guess 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD'
    cd build
}

# Uncomment the following line to do the above automatically.  It is
# not enabled by default because the correct files will be distributed
# with the tarball.
#fixconfigsubguess

mkdir -p android
cd android

PATH=$ANDROID_NDK_PATH/android-sdk-linux_x86/tools:$ANDROID_NDK_PATH/android-sdk-linux_x86/platform-tools:$ANDROID_NDK_STANDALONE_TOOLCHAIN/bin:$PATH

../../configure --host=arm-linux-androideabi --build=i686-pc-linux-gnu CC=arm-linux-androideabi-gcc

make
