<div align="center">
    <img src="doc/logo.png" height="100"/>
</div>

<div align="center">
DEKU (DExterous Kernel Update) - Utility for Linux kernel developers to quickly apply changes from the source code to the running kernel without the need for a system reboot.
</div>

https://github.com/user-attachments/assets/7039f450-62c5-426d-8bd0-e72b2d659cf1

## Table of Contents
- [About the DEKU](#about)
- [Android](#android)
- [ChromiumOS](#chromiumos)
- [Prerequisites](#prerequisites)
- [Download & build](#download)
- [Usage](#usage)
- [Use of patch files](#patch)
- [Root permissions](#root_permissions)
- [Supported kernel versions](#supported_kernel_versions)
- [Update DEKU to the latest version](#update_deku)
- [Constraints](#constraints)

<a name="about"></a>
## About the DEKU
The DEKU is a utility for quickly applying changes from the Linux kernel source code to a running kernel on the device. DEKU uses the kernel livepatching feature to apply changes to a running kernel. This tool is primarily intended for Linux kernel developers, but can also be useful for researchers to learn how the kernel works.

<a name="android"></a>
## For Android developers
Support for Android kernel development is coming soon.

<a name="chromiumos"></a>
## For ChromiumOS developers
Go to [ChromiumOS developers README](doc/CHROMIUMOS.md)

<a name="prerequisites"></a>
## Prerequisites
 - Installed `libelf`
 - Installed `libbinutils`
 - Installed `binutils-dev`
 - Installed `golang`
 - Enabled `CONFIG_LIVEPATCH` in kernel config  
 The above flag depends on the `KALLSYMS_ALL` flag that isn't enabled by default.
 - Kernel build artifacts
 - If changes are applied to the other device the SSH Key-Based authentication to the device must be configured. Also, the remote user must be able to load and unload kernel modules without prompts for password. See: [Root permissions](#root_permissions) section.

<a name="download"></a>
## Download & Build DEKU
Download and go to deku directory
```bash
git clone https://github.com/google/deku.git
cd deku
make
```

<a name="build_in_container"></a>
### Alternative build in container
```
docker run -it -v deku:/deku ubuntu bash
```
```
apt update
apt install -y gcc binutils-dev libelf-dev libiberty-dev build-essential golang
cd /deku
make
```

<a name="usage"></a>
## Usage
```bash
./deku -b <PATH_TO_KERNEL_BUILD_DIR> --target <USER@DUT_ADDRESS[:PORT]> [COMMAND]
```
```
Commands list:
    deploy [default]                      deploy the changes to the device. This is default command.
    livepatch                             build livepatch module.
    sync                                  synchronize information about kernel source code.
                                          It is recommended after fresh building the kernel to
                                          improve the reliability of DEKU, although it is not
                                          mandatory. However, when using the --src_inst_dir
                                          parameter, running this command after building the kernel
                                          is unnecessary, as DEKU's reliability is already enhanced
                                          by this parameter.

Available parameters:
    -b, --builddir                        path to kernel or out-of-tree module build directory.
    -k, --headersdir                      path to the kernel headers directory for the out-of-tree
                                          module in case the DEKU can't find the kernel headers
                                          This is the same parameter as the -C parameter for the
                                          `make` command in the Makefile.
    -s, --sourcesdir                      path to the kernel source directory. Use this parameter if
                                          DEKU can't find the kernel sources directory.
    -p, --patch                           patch file from which to generate livepatch module or
                                          apply changes to the device.
    --android_kernel                      path to main android kernel directory. It usually points
                                          to the "android-kernel" directory.
    --target=<USER@DUT_ADDRESS[:PORT]>    SSH connection parameter to the target device. The given
                                          user must be able to load and unload kernel modules. The
                                          SSH must be configured to use key-based authentication.
                                          Below is an example with this parameter.
    --ssh_options=<"-o ...">              options for SSH. Below is an example with this parameter.
    --src_inst_dir=<PATH>                 directory with the kernel sources that were installed
                                          after the kernel was built. Having this directory makes
                                          DEKU working more reliable. As an alternative to this
                                          parameter, the 'deku sync' command can be executed after
                                          the kernel has been built to make DEKU work more reliably.

-v, --verbose                             turn verbose mode.
-h, -?, --help                            print this information.
```

### Example usage
Use
```bash
./deku -b /home/user/linux_build --target=root@192.168.0.100
```
to apply changes to the kernel on the other device with the 192.168.0.100 IP address. This example uses `root` user, if non-root user is used see the [Root permissions](#root_permissions) section.

> \[!NOTE]
>
> Changes applied on the running kernel are not persistent and are life until the next reboot. After every reboot, the operation must be performed again.

Use
```bash
./deku -b /home/user/linux_build --target=root@192.168.0.100:2200
```
to apply changes to the kernel on the device with configured SSH port number to 2200.

Use
```bash
./deku -b /home/user/linux_build --target=root@192.168.0.100 --ssh_options="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ~/key_rsa"
```
when custom key-based authentication key is used for ssh connection

> \[!NOTE]
>
> Changes applied on the running kernel are not persistent and are life until the next reboot. After every reboot, the operation must be performed again.

Use
```bash
./deku -b /home/user/module --target=root@192.168.0.100
```
to apply changes to the out-of-tree module if the module was built in the /home/user/module directory.

Use
```bash
./deku -b /home/user/module -k /lib/modules/$(shell uname -r)/build --target=root@192.168.0.100
```
to apply changes to the out-of-tree module if DEKU can't find linux kernel headers.

Use
```bash
./deku sync
```
command after building the kernel to make DEKU work more reliably. The use of this command is not mandatory when the `--src_inst_dir` parameter is used.

To generate kernel livepatch module without deploy it on the target use
```bash
./deku -b /home/user/linux_build livepatch
```
command. Module is located in `workdir_XXXX/deku_YYYY_ZZZZ/deku_YYYY_ZZZZ.ko`

<a name="rest_of_readme"></a>

<a name="patch"></a>
## Use of patch files

https://github.com/user-attachments/assets/deb41694-e5fe-4cd3-87cc-69f16577475f

To generate a livepatch module from a patch file use the following command
```bash
./deku -b /home/user/linux_build -p file.patch livepatch
```
Livepatch module is located in  `workdir_XXXX/deku_YYYY_ZZZZ/deku_YYYY_ZZZZ.ko`

To apply patch on the running kernel use the following command
```bash
./deku -b /home/user/linux_build -p file.patch
```

It's also allowed to use wildcards to apply multiple patches, such as `-p 0001-*`, or the `-p | --patch` parameter can be passed multiple times.

<a name="root_permissions"></a>
## Root permissions
As apply changes to the running kernel are done by applying kernel modules it's required to have root privileges to do this. The `sudo` command is used by DEKU to gain privileges to load, unload kernel modules and to disable livepatch. To avoid having to pass the root password every time, the `sudoers` file can be modified to relax the rules for prompting for the password.
To do this add the following lines to the `/etc/sudoers` file:
```
username   ALL=(root) NOPASSWD: /usr/sbin/insmod deku_*, /usr/sbin/rmmod deku_*
username   ALL=(root) NOPASSWD: /usr/bin/tee --append /sys/kernel/livepatch/deku_*/enabled
```
change the `username` to name of user that will be used with DEKU.

If the DEKU is used to apply changes to the other device this rule must be applied on that device.

<a name="supported_kernel_versions"></a>
## Supported kernel versions
The minimum supported kernel version is: 5.4

<a name="update_deku"></a>
## Update DEKU to the latest version
```
git pull
make clean
make
```

<a name="constraints"></a>
## Constraints
 - Changes in the `.c' source file are fully supported. Header file changes are partially supported.
 - ARM and other architectures are not yet supported.
 - Functions marked as `__init`, `__exit` and some functions with the `notrace` are not supported.
 - Changes in struct fields are not yet supported. Only changes in the functions are permitted.
 - Changes to the lib/* directory are not supported.
 - Out-of-tree modules are not yet supported.
