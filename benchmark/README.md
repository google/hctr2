# Adiantum benchmark suite

This is the software we used to generate the benchmarks in our paper.

## Building and running

The following build instructions are written for users of Ubuntu and other
Debian-derived Linux systems; adjust as needed for your own platform.

### Preliminaries

1. Install [Ninja](https://ninja-build.org/):

       sudo apt-get install ninja-build

2. Install [Python](https://www.python.org/) version 3.6 or higher.

   If your Linux distribution provides this, simply install it:

       sudo apt-get install python3

   Otherwise (e.g. if your distro's `python3` is an older version such as 3.5),
   compile and install Python 3.6 yourself, then create a Python 3 [virtual
   environment](https://docs.python.org/3/library/venv.html).  For example:

       sudo apt-get install libz-dev libssl-dev
       wget https://www.python.org/ftp/python/3.6.7/Python-3.6.7.tar.xz
       tar xJf Python-3.6.7.tar.xz
       cd Python-3.6.7
       ./configure --prefix=$HOME/usr --enable-optimizations
       make -j$(getconf _NPROCESSORS_ONLN) install
       ~/usr/bin/python3.6 -m venv ~/python3.6-venv

       # Then run the following each time you need to set up the build environment.
       . ~/python3.6-venv/bin/activate

3. Install [Meson](https://mesonbuild.com/).

       pip install meson

4. Clone this repository and `cd` into the `benchmark` directory.

### Building and running on your host machine

Running the benchmarks on your host machine is convenient for development and a
good preliminary test, but the results it produces aren't currently very
meaningful since most algorithms don't have x86-optimized implementations
included in the benchmark suite yet.

* Set up the build directory: `meson build/host`
* Run the benchmarks: `ninja -C build/host output4096`
* Look at the output: `less build/host/output4096`

Note that for consistent results, the benchmark suite temporarily sets all CPUs
to their maximum frequency.  The code which does this assumes a Linux-based
system (e.g. Android) and requires root privileges.  On other systems, or as a
non-root user, you'll see warnings about being unable to set the CPU frequency.
You can ignore these if you don't need precise results on your host machine.

### Building and running on Android

Ensure you get host builds working first.

You will need a rooted Android device for this; otherwise we can't ensure the
CPUs are at maximum frequency. This test applies only to ARM-based devices.

* Install the [Android SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools).
* Restart the adb daemon in root mode: `adb root`
    * You'll need to do this every time the device reboots.
    * If this fails, it may mean your device is not rooted
* Install the [Android NDK](https://developer.android.com/ndk/)
* Set up a [standalone toolchain](https://developer.android.com/ndk/guides/standalone_toolchain)
* `export ANDROID_TOOLCHAIN=/path/to/android/toolchain`
* Clone and cd into this repository
* `./android-tools/setup-build --toolchain-prefix=$ANDROID_TOOLCHAIN/bin/arm-linux-androideabi-`
    * if `adb` is not in the `$PATH` then add the `--adb=/path/to/adb` argument
    * similarly with `--meson`
    * For an ARM64 build, add `--build-type=android-aarch64` and use
      `--toolchain-prefix=$ANDROID_TOOLCHAIN/bin/aarch64-linux-android-`.
* Run the benchmarks: `ninja -C build/android-arm output4096`
    * For an ARM64 build use `build/android-aarch64`, likewise below
* Look at the output: `less build/android-arm/output4096`

### Alternative implementations for Linux kernel

By default, most implementations in this benchmark suite optimize solely for
speed. However, in some cases the Linux kernel patches for Adiantum make
slightly different tradeoffs, considering concerns such as code size and power
consumption, and the additional overhead to using SIMD instructions in
kernel-mode when compared to userspace. To measure speed in a way more
representative of the Linux patches, set up the build with the "kernelish" option:

```sh
./android-tools/setup-build \
    --toolchain-prefix=$ANDROID_TOOLCHAIN/bin/arm-linux-androideabi- \
    --build-name=kernelish \
    --meson-arg=-Dkernelish=true
ninja -C build/kernelish output4096
```

## File layout

* `src/`: C sources for ciphers and benchmark driver
* `src/arm/`: ARM assembly
* `src/aarch64/`: ARM64 assembly
* `src/x86_64/`: x86_64 assembly
* `testvectors/`: Test vectors for Adiantum and HPolyC as C header files
* `../third_party/`: dependencies under the GPLv2 license, not MIT.
* `meson_options.txt`, `meson.build`: Meson build control files.
* `convert_testvecs.py`: converts test vectors from JSON to C header form
* `android-tools/setup-build`: Set up Android cross-compilation and
execution
* `android-tools/adb-exe-wrapper`: copies binaries to the Android device and
* runs them there
* `android-tools/android.xcompile`: Settings for Android cross-compilation,
read by `setup-build`
