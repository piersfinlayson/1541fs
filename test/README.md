# 1541fs-test

## Description

A simple test program that verifies that you have the necessary pre-requisites installed and hardware setup.  Assumes you have a single XUM1541 with a single 1541 connected, and turned on, set as device 8, with a blank (formatted or unformatted) disk.

Operation:
* Formats the disk (if so requested)
* Writes a file
* Reads it back
* Deletes the file
* Lists the directory at multiple points

## Building and running

From this directory:

```
make
./1541fs-test
```