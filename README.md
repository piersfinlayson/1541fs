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

If you get this error:

```
error: cannot query product name: error sending control message: Operation not permitted
error: no xum1541 device found
```

It is likely because you need to modify the udev rule OpenCBM installed.  Edit ```/etc/udev/rules.d/45-opencbm-xum1541.rules```.  In this file Tag+="uaccess" means provide access to shells running on the console.  You may not be.

Instead, change the ```TAG_="uaccess"``` to ```USER="username"``` where username is your username.  Then restart udev with:

```
sudo service udev reload
```

## Using Windows Subsystem for Linux (WSL)

To use your XUM1541 with WSL, you need to install usbipd.  Use the .msi Installer from here: https://github.com/dorssel/usbipd-win/releases

Once usbipd is installed, attached your XUM1541 to your Windows machine that you are using WSL on.

Then open a Powershell with Administrator privileges.

Run:

```
usbipd list
```

You should see an output like this:

```
Connected:
BUSID  VID:PID    DEVICE                                                        STATE
1-3    16d0:0504  xum1541 floppy adapter (ZOOMFLOPPY)                           Attached
1-7    05c8:03c0  HD Camera                                                     Not shared
1-10   8087:0aaa  Intel(R) Wireless Bluetooth(R)                                Not shared

Persisted:
GUID                                  DEVICE

```

Note the bus ID of the XUM1541 - here it is 1-3.  You now need to bind the XUM1541 using the bus ID:

```
usbipd bind -b 1-3
```

Now you need to attached the device to WSL, like this, again using the correct bus ID:

```
usbipd attach --wsl -b 1-3 
```

If you now run ```sudo dmesg``` on your WSL instance, you should see your XUM1541 appear.

Note there is also an auto-attach option in usbipd (-a|--auto-attach).  This keeps usbipd running in the powershell, so if you unplug and replug the device it should be attached and detached automatically.


