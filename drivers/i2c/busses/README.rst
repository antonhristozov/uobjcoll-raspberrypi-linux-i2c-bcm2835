Building and Testing an i2c driver for Raspberry Pi 3B+
-------------------------------------------------------

BEFORE YOU BEGIN

Make sure that you are on uobjcoll-4.4.y branch, which is a dervied from the rpi-4.4.y branch

HOW TO BUILD

Follow the instructions on this page for the section 
"Install and build RPI kernel on development system" :
https://uberxmhf.org/docs/rpi3-cortex_a53-armv8_32/build.html

HOW TO INSTALL

Follow the instructions on this page. For the kernel only with no hypervisor
one needs only steps 10 to 16:
https://uberxmhf.org/docs/rpi3-cortex_a53-armv8_32/installing.html

DRIVER MODIFICATIONS AND TESTING

Changing the source code of the driver i2c-bcm2708.c in drivers/i2c/busses and recompilation can happen
 using the following command:
make -j 24 ARCH=arm CROSS_COMPILE=~/tools/arm-bcm2708/arm-rpi-4.9.3-linux-gnueabihf/bin/arm-linux-gnueabihf- modules

Deploying the modfied driver on the target can happen with scp. 
For example the following command will transfer the .ko file to the /home/pi folder.

scp i2c-bcm2708.ko pi@ip_address_of_pi:

The driver can loaded with the following command:

insmod ./i2c-bcm2708.ko

The driver can be unloaded with the command:

rmmod ./i2c-bcm2708.ko

All drivers running on the system can be seen with:

lsmod
