# SPDX-License-Identifier: GPL-2.0
obj-m += scalelfs.o

scalelfs-y		:= dir.o file.o inode.o namei.o hash.o super.o inline.o
scalelfs-y		+= checkpoint.o gc.o data.o node.o segment.o recovery.o
scalelfs-y		+= shrinker.o extent_cache.o sysfs.o lockfree_list.o
scalelfs-$(CONFIG_FS_VERITY) += verity.o

default:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

lock_test: rm_lock_test
	$(CC) test_range_lock.c lockfree_list.c -o lock_test -lpthread $(shell pkg-config --cflags --libs glib-2.0) -g

rm_lock_test:
	rm -f lock_test
