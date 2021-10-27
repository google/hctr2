# HCTR2 benchmark suite

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
good preliminary test.

* Set up the build directory: `meson build/host`
* Build cipherbench: `ninja -C build/host`
* Run cipherbench: `./build/host/cipherbench --bufsize=4096`

Note that for consistent results, the benchmark suite temporarily sets all CPUs
to their maximum frequency.  The code which does this assumes a Linux-based
system (e.g. Android) and requires root privileges.  On other systems, or as a
non-root user, you'll see warnings about being unable to set the CPU frequency.
You can ignore these if you don't need precise results on your host machine.

### Building for aarch64 and running in Qemu

Ensure you get host builds working first.

* Install [qemu-user](https://qemu-project.gitlab.io/qemu/user/index.html) `sudo apt install qemu-user`.
* Install aarch64-binutils `sudo apt install binutils-aarch64-linux-gnu`.
* Install gcc for aarch64 `sudo apt install gcc-aarch64-linux-gnu`.
* Set up the build directory: `meson --cross-file aarch64.ini --cross-file cross.ini build/aarch64`
* Build cipherbench: `ninja -C build/aarch64`
* Run cipherbench: `qemu-aarch64 -L /usr/aarch64-linux-gnu ./build/host/cipherbench --bufsize=4096`

## File layout

* `src/`: C sources for ciphers and benchmark driver
* `src/aarch64/`: ARM64 assembly
* `src/x86_64/`: x86_64 assembly
* `testvectors/`: Test vectors for HCTR2 as C header files
* `../third_party/`: dependencies under the GPLv2 license, not MIT.
* `meson.build`: Meson build control files
