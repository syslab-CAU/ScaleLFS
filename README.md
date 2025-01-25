# ScaleLFS: A Log-Structured File System with Scalable Garbage Collection for Commodity SSDs

## Directory
```bash
cd ./ScaleLFS
```

## Build & Install
1.Install provided kernel version
* Refer to following link (https://docs.kernel.org/kbuild/index.html)

2.Boot with installed kernel

3.Build ScaleLFS kernel module
```bash
cd ./ScaleLFS
make
```

4.Build mkfs tool
* Refer to ScaleLFS/f2fs-tools/README or
```bash
cd ./ScaleLFS/f2fs-tools/
./autogen.sh
./configure
make
```

## MKFS
* Example (mkfs for /dev/nvme0n1)
```bash
sudo ScaleLFS/f2fs-tools/mkfs/mkfs.f2fs /dev/nvme0n1
```

## Mount
* Example (mount /dev/nvme0n1 to /mnt)
```bash
sudo insmod ScaleLFS/scalelfs.ko
sudo mount -t f3fs /dev/nvme0n1 /mnt
```
