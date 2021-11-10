# HCTR2 benchmark tool

This is a testing and benchmarking tool for HCTR2, containing C and assembly
(x86_64 and aarch64) implementations.  The HCTR2 construction is implemented in
C, but it uses C or assembly implementations of AES-XCTR and POLYVAL.  The tool
supports running self-tests and benchmarks for all these algorithms.

## Building and running

The following build instructions are written for users of Ubuntu and other
Debian-derived Linux systems; adjust as needed for your own platform.

### Preliminaries

1. Install [Python](https://www.python.org/) version 3.6 or higher,
   [Meson](https://mesonbuild.com/), and [Ninja](https://ninja-build.org/):

       sudo apt-get install python3 meson ninja-build

2. Clone this repository and `cd` into the `benchmark` directory.

### Running on your host machine

This will test the x86_64 assembly code (assuming that your host machine is
x86_64) and the generic code.

1. Set up the build directory:

       meson build/host

2. Build the benchmark tool:

       ninja -C build/host

3. Run the benchmark tool:

       ./build/host/cipherbench

### Running on Android (aarch64)

This will test the aarch64 assembly code and the generic code.

1. Download the [Android NDK](https://developer.android.com/ndk/downloads).

2. Connect an Android device and get `adb` access.

3. If the device is rooted, run `adb root` to restart `adb` with root
   privileges.  This isn't required, but it will give more accurate results.

4. Set up the build directory, providing the path to your NDK directory:

       ./cross-tools/setup-build --build-type=android-aarch64 --ndk-dir=/path/to/ndk/dir

5. Build the benchmark tool:

       ninja -C build/android-aarch64

6. Run the benchmark tool:

       cross-tools/adb-exe-wrapper adb ./build/android-aarch64/cipherbench

### Running using QEMU user-mode emulation (aarch64)

This method allows testing the aarch64 assembly code without a real device.
Note that the benchmark results won't be very useful in this case.

1. Install prerequisite packages:

       sudo apt-get install qemu-user binutils-aarch64-linux-gnu gcc-aarch64-linux-gnu

2. Set up the build directory:

       ./cross-tools/setup-build --build-type=qemu-aarch64

3. Build the benchmark tool:

       ninja -C build/qemu-aarch64

4. Run the benchmark tool:

       qemu-aarch64 -L /usr/aarch64-linux-gnu ./build/qemu-aarch64/cipherbench

### Tips and tricks

By default, the benchmarks are run using 4096-byte messages and are repeated 5
times for each algorithm, with the fastest speed being chosen.  These parameters
can be configured via the `--bufsize` and `--ntries` options.

To prevent CPU frequency scaling from causing inconsistent results, the
benchmark tool tries to temporarily set all CPUs to their maximum frequency.
The code which does this assumes a Linux-based system (e.g. Android) and
requires root privileges.  On other systems, or as a non-root user, you'll see
warnings about being unable to set the CPU frequency.  You can ignore these if
you don't need precise results.

Instead of manually running the tool, you may instead pass one of the predefined
run targets to the `ninja` command, e.g. `ninja -C build/host output4096`.

## File layout

* `src/`: C sources for ciphers and benchmark driver
* `src/aarch64/`: ARM64 assembly
* `src/x86_64/`: x86_64 assembly
* `../third_party/`: dependencies under the GPLv2 license, not MIT.
* `meson.build`: Meson build control files
* `cross-tools/`: Cross compilation support files
