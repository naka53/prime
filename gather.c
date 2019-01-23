#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

int init_module(void) {
  int i;
  unsigned char *do_syscall_64 = (unsigned char *)0xffffffff81003af0;
  unsigned char *entry_SYSCALL_64 = (unsigned char *)0xffffffff81618f10;

  printk(KERN_INFO "prime module started\n");

  printk(KERN_INFO "entry_SYSCALL_64\n");
  for (i = 0; i < 1024; i += 8)
    printk(KERN_INFO "%p : %02x %02x %02x %02x %02x %02x %02x %02x\n",
	   entry_SYSCALL_64 + i,
	   entry_SYSCALL_64[i],
	   entry_SYSCALL_64[i + 1],
	   entry_SYSCALL_64[i + 2],
	   entry_SYSCALL_64[i + 3],
	   entry_SYSCALL_64[i + 4],
	   entry_SYSCALL_64[i + 5],
	   entry_SYSCALL_64[i + 6],
	   entry_SYSCALL_64[i + 7]);

  printk(KERN_INFO "do_syscall_64\n");
  for (i = 0; i < 1024; i += 8)
    printk(KERN_INFO "%p : %02x %02x %02x %02x %02x %02x %02x %02x\n",
	   do_syscall_64 + i,
	   do_syscall_64[i],
	   do_syscall_64[i + 1],
	   do_syscall_64[i + 2],
	   do_syscall_64[i + 3],
	   do_syscall_64[i + 4],
	   do_syscall_64[i + 5],
	   do_syscall_64[i + 6],
	   do_syscall_64[i + 7]);
}
