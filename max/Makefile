# SPDX-License-Identifier: GPL-2.0
obj-m += max.o

max-y		:= dir.o file.o inode.o namei.o hash.o super.o inline.o
max-y		+= checkpoint.o gc.o data.o node.o segment.o recovery.o
max-y		+= shrinker.o extent_cache.o sysfs.o rps.o
max-$(CONFIG_FS_VERITY) += verity.o

default:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
