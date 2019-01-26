#include <linux/kernel.h>
#include <linux/module.h>

#define DUMP_SIZE 1024

MODULE_LICENSE("GPL");

int init_module(void) {
  int i;
  unsigned char *do_syscall_64 = (unsigned char *)0xffffffff81003af0;
  unsigned char *entry_SYSCALL_64 = (unsigned char *)0xffffffff81618f10;

  printk(KERN_INFO "gather module started");

  printk(KERN_INFO "entry_SYSCALL_64");
  for (i = 0; i < DUMP_SIZE; i += 8)
    printk(KERN_INFO "%llx : %02x %02x %02x %02x %02x %02x %02x %02x",
	   (unsigned long long)(entry_SYSCALL_64 + i),
	   entry_SYSCALL_64[i],
	   entry_SYSCALL_64[i + 1],
	   entry_SYSCALL_64[i + 2],
	   entry_SYSCALL_64[i + 3],
	   entry_SYSCALL_64[i + 4],
	   entry_SYSCALL_64[i + 5],
	   entry_SYSCALL_64[i + 6],
	   entry_SYSCALL_64[i + 7]);

  printk(KERN_INFO "do_syscall_64");
  for (i = 0; i < DUMP_SIZE; i += 8)
    printk(KERN_INFO "%llx : %02x %02x %02x %02x %02x %02x %02x %02x",
	   (unsigned long long)(do_syscall_64 + i),
	   do_syscall_64[i],
	   do_syscall_64[i + 1],
	   do_syscall_64[i + 2],
	   do_syscall_64[i + 3],
	   do_syscall_64[i + 4],
	   do_syscall_64[i + 5],
	   do_syscall_64[i + 6],
	   do_syscall_64[i + 7]);
}

void cleanup_module(void) {
  printk(KERN_INFO "gather module stopped");
}
