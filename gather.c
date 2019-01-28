#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>

#define DUMP_SIZE 512

MODULE_LICENSE("GPL");

int init_module(void) {
  int i;
  unsigned char *do_syscall_64 = (unsigned char *)0xffffffff81003af0;
  unsigned char *entry_SYSCALL_64 = (unsigned char *)0xffffffff81618f10;
  unsigned char **sys_call_table = (unsigned char **)0xffffffff82000100;
  
  printk(KERN_INFO "gather module started");
  for (i = 0; i < DUMP_SIZE; i+= 8)
    printk(KERN_INFO "%llx : %02x %02x %02x %02x %02x %02x %02x %02x",
	   (unsigned long long)(sys_call_table[__NR_close] + i),
	   sys_call_table[__NR_close][i],
	   sys_call_table[__NR_close][i + 1],
	   sys_call_table[__NR_close][i + 2],
	   sys_call_table[__NR_close][i + 3],
	   sys_call_table[__NR_close][i + 4],
	   sys_call_table[__NR_close][i + 5],
	   sys_call_table[__NR_close][i + 6],
	   sys_call_table[__NR_close][i + 7]);
  /*
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
  */
  return 0;
}

void cleanup_module(void) {
  printk(KERN_INFO "gather module stopped");
}
