#
# Makefile for the i2c core.
#

obj-$(CONFIG_I2C_BOARDINFO)	+= i2c-boardinfo.o
obj-$(CONFIG_I2C)		+= i2c-core.o
obj-$(CONFIG_I2C_SMBUS)		+= i2c-smbus.o
obj-$(CONFIG_I2C_CHARDEV)	+= i2c-my-dev.o
i2c-my-dev-objs += i2c-dev.o ../../../uberxmhf/uxmhf-rpi3/rgapps/linux/libs/libkhcall/libkhcall.a
CFLAGS_i2c-dev.o := -DHMAC_DIGEST -DUOBJCOLL -I/home/anton/uberwork/uberxmhf/uxmhf-rpi3/rgapps/linux/libs/libkhcall/include/ -I/home/anton/uberwork/uberxmhf/uxmhf-rpi3/uobjcoll/uobjs/main/include -I.
obj-$(CONFIG_I2C_MUX)		+= i2c-mux.o
obj-y				+= algos/ busses/ muxes/
obj-$(CONFIG_I2C_STUB)		+= i2c-stub.o
obj-$(CONFIG_I2C_SLAVE_EEPROM)	+= i2c-slave-eeprom.o

ccflags-$(CONFIG_I2C_DEBUG_CORE) := -DDEBUG
CFLAGS_i2c-core.o := -Wno-deprecated-declarations
