# OP-TEE OS for Raspberry Pi 4
## Introduction

This repository provides a step-by-step guide to enable OP-TEE (Open Portable Trusted Execution Environment) support on the Raspberry Pi 4 (RPI4) board. OP-TEE is a secure execution environment designed to run trusted applications alongside a rich operating system. The goal of this project is to create a standardized and up-to-date guide for integrating OP-TEE with the RPI4.
Prerequisites

Before proceeding, ensure that you have the following tools and hardware:

- A Linux machine (other than the RPI4 itself) with a micro-SD card reader and an Ethernet port. This guide was tested on Ubuntu 22.04 LTS.
- A USB-UART capable connection, such as an FTDI cable (an FT232 was used in this guide).
- (Optional) An RJ45 Ethernet cable.

## Disclaimer

Important: The OP-TEE port for the Raspberry Pi 4 is NOT SECURE. It is provided solely for educational purposes and prototyping. Do not use it in a production environment or with sensitive data.
## Step 1: Generate the Rich Operating System

This step involves installing Buildroot, configuring the build, and compiling the Linux kernel.
### Step 1.1: Installing Buildroot

    Open a console and create a directory for the project:
```
mkdir OPTEE-RPI4
cd OPTEE-RPI4/
```
    Install the required packages:
```
sudo apt update && sudo apt upgrade
sudo apt install sed make binutils build-essential diffutils gcc g++ bash patch gzip bzip2 perl tar cpio unzip rsync file bc findutils
sudo apt install git libncurses5 libncurses5-dev python3 curl
```
    Clone the Buildroot repository:
```
git clone git://git.buildroot.net/buildroot
cd buildroot/
```
    Configure Buildroot for the RPI4:
```
make raspberrypi4_64_defconfig
```
### Step 1.2: Configuring the Build

    Create a kernel configuration fragment file:
```
mkdir linux-rpi
cd linux-rpi/
touch kernel-optee.cfg
```
    Open kernel-optee.cfg and add the following lines:
```
CONFIG_TEE=y
CONFIG_OPTEE=y
```
Run make menuconfig and configure the build options:
- Set the Additional configuration fragment files
- Disable getty
- Set a root password
- Enable DHCP, Dropbear, and optee-client
- Enable optee-os and optee-examples
- Enable filesystem compression images
    
Save the configuration and start the build process:
```
make -j$(nproc)
```
### Step 1.3: Configuring the Kernel

Configure the kernel:
```
make linux-menuconfig
```
- Enable "Trusted Execution Environment support" and save the configuration.

## Step 2: Update the ARM Trusted Firmware

Clone the ARM Trusted Firmware repository:
```
cd ../
git clone https://github.com/ARM-software/arm-trusted-firmware
cd arm-trusted-firmware/
git reset --hard 0cf4fda
```
Open plat/rpi/common/rpi4_bl31_setup.c and replace the bl31_early_platform_setup2 function with the provided code.

## Step 3: Update OP-TEE OS

Clone the OP-TEE OS repository:
```
cd ../../
git clone https://github.com/OP-TEE/optee_os
cd optee_os
git reset --hard 6376023
```
Create a new platform for the RPI4:
```
cd core/arch/arm
cp -rf plat-rpi3 plat-rpi4
cd plat-rpi4
```
Open platform_config.h and update the UART base address and clock frequency.

## Step 4: Compile the ARM Trusted Firmware and the Trusted OS

Set up the toolchain:
```
cd ../../../../
git clone https://github.com/OP-TEE/build.git
cd build/
make -f toolchain.mk -j2
export PATH=/.../OPTEE-RPI4/toolchains/aarch64/bin:$PATH
```
Create a Makefile in the OPTEE-RPI4 directory with the provided content.
Run make to compile the ARM Trusted Firmware and the Trusted OS.

## Step 5: Set up the Raspberry Pi 4
### Step 5.1: Device Tree Fix

Create an optee-fix.dts file with the provided content.
Compile the .dts file to generate optee-fix.dtbo:
```
cd buildroot/output/build/linux-custom/scripts/dtc
./dtc /.../OPTEE-RPI4/optee-fix.dts > /.../OPTEE-RPI4/optee-fix.dtbo
```
Copy optee-fix.dtbo to the firmware overlays directory:
```
cp optee-fix.dtbo ../../../../../../images/rpi-firmware/overlays/
```
### Step 5.2: Edit config.txt and cmdline.txt

Create config.txt and cmdline.txt files with the provided content.
Copy the files and bl31-bl32.bin to the images/rpi-firmware/ directory.
Rebuild the Linux image:
```
cd ../../../
make -j$(nproc)
```
## Step 6: Flash and Test
### Step 6.1: Flashing the SD Card

Insert the SD card into your computer and back up any important data.
Identify the SD card device name using lsblk.
Flash the generated SD card image:
```
sudo dd if=buildroot/output/images/sdcard.img of=/dev/sdX
```
### Step 6.2: Establish Serial Port Communication

Connect the FTDI cable to the RPI4 and your computer.
Install Picocom and configure the user permissions:
```
sudo apt install picocom
sudo usermod -a -G dialout $USER
```
Start Picocom with the correct baudrate and port:
```
sudo picocom -b 115200 /dev/ttyUSB0
```
### Step 6.3: (Optional) Set up SSH Connection

Configure the DHCP server and install the SSH server on your computer.
Turn off the RPI4.

### Step 6.4: Turn on the RPI4

Insert the flashed SD card into the RPI4 and power it on.
Verify the boot process and OP-TEE initialization in the serial terminal.

### Step 6.5: (Optional) Connect via SSH

Obtain the RPI4's IP address using the arp command.
Establish an SSH connection to the RPI4 using the obtained IP address.

### Step 6.6: Test OP-TEE

Run the optee_example_hello_world command to test the OP-TEE installation.
Observe the output in the serial terminal and/or SSH session.

## Conclusion

By following these steps, you should have successfully enabled OP-TEE support on your Raspberry Pi 4 board. Keep in mind the disclaimer about the insecure nature of this port and use it only for educational and prototyping purposes.
