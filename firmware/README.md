With my XUM1541 I hit the problem described in this github issue: https://github.com/OpenCBM/OpenCBM/issues/108

The 11ce3435 firmware linked to in that issue claims to fixes the problem - but for me it didn't.

To flash it run this command (from this directory):

```
xum1541cfg update -f xum1541-ZOOMFLOPPY-v08-11ce3435.hex
```

If you hit problems add the ```-v``` switch to the command.

Here is expected output:

```
finding and preparing device for update...
scanning usb ...
scanning bus 002
  device 1d6b:0003 at 001
scanning bus 001
  device 16d0:0504 at 016
    found xu/xum1541 version 0208, device 016
    xum1541 name: xum1541 floppy adapter (ZOOMFLOPPY)
    xum1541 serial number:   0
note: device has version 8 but firmware is not newer (version 8)
warning: version mismatch but proceeding to update anyway
updating firmware...
Validating...
update completed ok!
```