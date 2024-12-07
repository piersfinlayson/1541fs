# 1541fs

## Introduction

1541fs provides linux-based filesystem support for physical Commodore disk drives, such as the 1541, allowing the drives to be mounted within linux, and the files accessed natively.

It requires an XUM1541 USB-IEC (or parallel, or IEEE-488) device to connect the drives to the linux machine.

## Building and running

### Installiing pre-requisities

```
sudo apt -y install build-essential autoconf automake libtool flex libusb-dev libncurses5-dev fuse3 libfuse3-dev
```

### Getting cc65

```
git clone https://github.com/cc65/cc65
cd cc65
make
sudo make install
cd ..
```

### Getting OpenCBM

```
git clone https://github.com/OpenCBM/OpenCBM
cd OpenCBM
make -f LINUX/Makefile
sudo make -f LINUX/Makefile install
sudo make -f LINUX/Makefile install-plugin
sudo cp xum1541/udev/45-opencbm-xum1541.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

### Getting 1541fs 

```
git clone https://github.com/piersfinlayson/1541fs
cd 1541fs
cd test
make
./1541fs-test
```

If you get this error:

```
./1541fs-test: error while loading shared libraries: libopencbm.so.0: cannot open shared object file: No such file or directory
```

You need to export an appropriate LD_LIBRARY_PATH, such as:

```
export LD_LIBRARY_PATH=/usr/local/lib
```