# 1541fs

## Building and running

### Installiing pre-requisities

```
sudo apt -y install build-essential autoconf automake libtool flex libusb-dev libncurses5-dev
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
