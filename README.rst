How to Compile and Test an i2c Driver for Raspberry Pi 3B+
----------------------------------------------------------

ASSUMPTIONS

- The branch used for the Raspbian OS is uobjcoll-4.4.y which is a dervied from rpi-4.4.y branch.
- The driver that we are building and testing is i2c-bcm2708.c and the produced module is i2c-bcm2708.ko
- The newer driver i2c-bcm2835.ko can also be built, but is for a newer version of the kernel and is not part of this development.
- The source files for the i2c drivers afe located in folder drivers/i2c/busses.
- The Raspberry Pi has to have the same kernel so that the drivers can work

BUILDING AND TESTING

All details on how to compile, deploy and test the driver and kernel to a Raspberry Pi 3B+ are given in the respective README.rst file located in drivers/i2c/busses folder
