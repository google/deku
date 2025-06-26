<h1 align="center">
    <img src="logo.png" height="150"/>
</h1>

<div align="center">
    <img src="chromiumos_logo.svg" width="100">

# DEKU for Android
</div>

## Table of Contents
- [Prerequisites](#prerequisites)
- [Install](#install)
- [Usage](#usage)

---

<a name="prerequisites"></a>
## Prerequisites
 - Build the kernel with: `USE="livepatch" emerge-${BOARD} chromeos-kernel-${KERNEL_VERSION}`  
Optionally add the `kernel_sources` parameter to the `USE` variable which a little bit speedup the DEKU.
 - Flash the kernel to the device.

<a name="install"></a>
## Download & Build DEKU
Clone DEKU repository
```bash
git clone 
```
```bash
sudo emerge deku
```

<a name="usage"></a>
## Usage
Use following command to apply changes to the kernel on the DUT.
```bash
deku --target=<DUT_ADDRESS[:PORT]>
```

Adjust `--target=<DUT_ADDRESS[:PORT]>` for Chromebook address and optionally SSH port number.

### Example use:
`deku --target=192.168.0.100`

***
[Read the rest of the README](../README.md#rest_of_readme)
