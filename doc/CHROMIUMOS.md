<h1 align="center">
    <img src="logo.png" height="150"/>
</h1>

<div align="center">
    <img src="chromiumos_logo.svg" width="100">

# DEKU for ChromiumOS
</div>

## Table of Contents
- [About the DEKU](#about)
- [Prerequisites](#prerequisites)
- [Download & build](#download)
- [Usage](#usage)

---

<a name="about"></a>
## About the DEKU for ChromiumOS
Since DEKU includes integrations for the ChromiumOS SDK, it can be used in an easier way.
<a name="prerequisites"></a>
## Prerequisites
 - Build the kernel with: `USE="livepatch" emerge-${BOARD} chromeos-kernel-${KERNEL_VERSION}`  
Optionally add the `kernel_sources` parameter to the `USE` variable which a little bit speedup the DEKU.
 - Flash the kernel to the device.

<a name="download"></a>
## Download and build DEKU
Download and build DEKU inside cros sdk environment
```bash
git clone https://github.com/google/deku.git
cd deku
make
```

<a name="usage"></a>
## Usage
Use following command to apply changes to the kernel on the DUT.
```bash
./deku --target=<DUT_ADDRESS[:PORT]>
```

Adjust `--target=<DUT_ADDRESS[:PORT]>` for Chromebook address and optionally SSH port number.

### Example use:
`./deku --target=192.168.0.100`

***
[Read the rest of the README](../README.md#rest_of_readme)
