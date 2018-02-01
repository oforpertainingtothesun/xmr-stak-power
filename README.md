# XMR-Stak-SPARC - Monero mining software for SPARC T4 and later

XMR-Stak-SPARC is a universal Stratum pool miner and a fork of XMR-Stak-CPU. There is also an [AMD GPU version](https://github.com/fireice-uk/xmr-stak-amd) and an [NVIDIA GPU version](https://github.com/fireice-uk/xmr-stak-nvidia)

## HTML and JSON API report configuraton

To configure the reports shown above you need to edit the httpd_port variable. Then enable wifi on your phone and navigate to [miner ip address]:[httpd_port] in your phone browser. If you want to use the data in scripts, you can get the JSON version of the data at url [miner ip address]:[httpd_port]/api.json

## Compile guides

### Solaris 11.3

This procedure has been tested on Solaris 11.3 only, YMMV.

This was required because Solaris ships gcc-4.8 built with Solaris native as - which understands the `aes_eround01` etc... instructions but ships gcc-5.4 with gnu as from 2013 (2.23) which does not. If you compile something with inline assembly that has the `aes_eround01` instructions in different instructions are emmitted and an illegal instruction is thrown.

The flags that gcc is built with are pulled from the output of `/usr/gcc/4.8/bin/gcc -v`.

1. Make sure the packages are found:
   ```
   pkg install gcc gmp mpc mpfr cmake
   ```
2. Download gcc-5.5.0
3. Build gcc-5.5.0
   ```
   tar xvf gcc-5.5.0
   mkdir build
   cd build
   ../gcc-5.5.0/configure --prefix=/usr/gcc/5.5 --mandir=/usr/gcc/5.5/share/man --bindir=/usr/gcc/5.5/bin --libdir=/usr/gcc/5.5/lib --sbindir=/usr/gcc/5.5/sbin --infodir=/usr/gcc/5.5/share/info --libexecdir=/usr/gcc/5.5/lib --enable-languages=c,c++ --enable-shared --with-gmp-include=/usr/include/gmp --with-mpfr-include=/usr/include/mpfr --without-gnu-ld --with-ld=/usr/bin/ld --without-gnu-as --with-as=/usr/bin/as CFLAGS='-g -O2  -mtune=ultrasparc -mcpu=ultrasparc -mno-unaligned-doubles' CXXFLAGS='-g -O2 -mtune=ultrasparc -mcpu=ultrasparc -mno-unaligned-doubles'
   gmake -j 16
   gmake install
   ```
4. Build and install google test
   ```
   git clone https://github.com/google/googletest.git
   mkdir build
   cd build
   CXXFLAGS='-m64' CFLAGS='-m64' CXX=/usr/gcc/5.5/bin/g++ cmake ../googletest
   gmake -j 16
   gmake install
   ```
5. Build and install
   ```
   git clone https://github.com/oforpertainingtothesun/xmr-stak-sparc
   mkdir build
   cd build
   CXXFLAGS='-m64' CFLAGS='-m64' CXX=/usr/gcc/5.5/bin/g++ cmake ../xmr-stak-sparc \
       -DHWLOC_ENABLE=OFF \
       -DMICROHTTPD_ENABLE=OFF \
       -DCMAKE_INSTALL_PREFIX=/usr/local/xmr-stak-sparc
   gmake -j 16 install
   ```

### Solaris 11.4 (beta)

It looks like Oracle have upgraded binutils sufficiently for their gcc 5.4 version to correctly work with hardware AES. This has been tested, but not quite fully, on Solaris 11.4 (beta).

1. Make sure that gcc-5.4 is available:
   ```
   pkg change-facet 'facet.version-lock.*=false'
   ```
2. Install g++ and dependencies
   ```
   pkg install gcc@5.4 cmake
   ```
3. Go to step 4 of Solaris 11.3 guide.

### Notes:

* *CMake 3:* This dependency has been removed but this means that config.txt will be overwritten by the built file under install if it is not used.
* *RPath handling*: This has to be done at build-time at the moment but a better way is being figured out.

## Donate!

If you have SPARC hardware available you are probably rich, so please donate to my address!

oforpertainingtothesun
```
444jF3JDkjVgf3wc4SSWbmTqkbANndx3YEnCt2F2zQsTEuVAsFVJf5XgGuM9Y5nGPPeLCAk8WG7tdTSkGwYxTfwWJaXej5g
```

Conversion to work with PPC (le):

nioroso-x3:
```
42UwBFuWj9uM7RjH15MXAFV7oLWUC9yLTArz4bmD3gbVWu1obYRUDe8K9v8StqXPhP2Uz1BJZgDQTUVhvT1cHFMBHA6aPg2
```

Original developers:

fireice-uk:
```
4581HhZkQHgZrZjKeCfCJxZff9E3xCgHGF25zABZz7oR71TnbbgiS7sK9jveE6Dx6uMs2LwszDuvQJgRZQotdpHt1fTdDhk
```

psychocrypt:
```
43NoJVEXo21hGZ6tDG6Z3g4qimiGdJPE6GRxAmiWwm26gwr62Lqo7zRiCJFSBmbkwTGNuuES9ES5TgaVHceuYc4Y75txCTU
```

## Advanced Compile Options

The build system is CMake, if you are not familiar with CMake you can learn more [here](https://cmake.org/runningcmake/).

### Short Description

There are two easy ways to set variables for `cmake` to configure *xmr-stak-cpu*
- use the ncurses GUI
  - `ccmake .`
  - edit your options
  - end the GUI by pressing the key `c`(create) and than `g`(generate)
- set Options on the command line
  - enable a option: `cmake . -DNAME_OF_THE_OPTION=ON`
  - disable a option `cmake . -DNAME_OF_THE_OPTION=OFF`
  - set a value `cmake . -DNAME_OF_THE_OPTION=value`

After the configuration you need to call
`make install` for slow sequential build
or
`make -j install` for faster parallel build
and install.

### xmr-stak-sparc Compile Options
- `CMAKE_INSTALL_PREFIX` install miner to the home folder
  - `cmake . -DCMAKE_INSTALL_PREFIX=$HOME/xmr-stak-cpu`
  - you can find the binary and the `config.txt` file after `make install` in `$HOME/xmr-stak-cpu/bin`
- `CMAKE_LINK_STATIC` link libgcc and libstdc++ libraries static (default OFF)
  - disable with `cmake . -DCMAKE_LINK_STATIC=ON`
-`CMAKE_BUILD_TYPE` set the build type
  - valid options: `Release` or `Debug`
  - you should always keep `Release` for your productive miners
- `MICROHTTPD_ENABLE` allow to disable/enable the dependency *microhttpd*
  - by default enabled
  - there is no *http* interface available if option is disabled: `cmake . -DMICROHTTPD_ENABLE=OFF`
- `OpenSSL_ENABLE` allow to disable/enable the dependency *OpenSSL*
  - by default enabled
  - it is not possible to connect to a *https* secured pool if option is disabled: `cmake . -DOpenSSL_ENABLE=OFF`
- `HWLOC_ENABLE` allow to disable/enable the dependency *hwloc*
  - by default enabled
  - the config suggestion is not optimal if option is disabled: `cmake . -DHWLOC_ENABLE=OFF`

