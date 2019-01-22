#include <linux/kernel.h>
#include <linux/module.h>
 
MODULE_LICENSE("GPL");

int init_module(void) {
  int i;
  /*
  int do_syscall_64_offset;
  int sys_call_table_offset;
  unsigned char *do_syscall_64;
  unsigned long long *sys_call_table;
  unsigned char *entry_SYSCALL_64 = (unsigned char*)(native_load_gs_index - 4032);
  */
  //unsigned long long *sys_call_table      = (unsigned long long *)0xffffffff81800200;
  //unsigned long long *ia32_sys_call_table = (unsigned long long *)0xffffffff818015c0;
  unsigned char *do_syscall_64              = (unsigned char *)0xffffffff81003af0;
  unsigned char *entry_SYSCALL_64           = (unsigned char *)0xffffffff81618f10;
  
  printk(KERN_INFO "prime module started\n");

  printk(KERN_INFO "entry_SYSCALL_64\n");
  for (i = 0; i < 4032; i += 8)
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
  
  /*
  for (i = 0; i < 4032; i++) {
    if (entry_SYSCALL_64[i    ] == 0x4d &&
	entry_SYSCALL_64[i + 1] == 0x31 &&
	entry_SYSCALL_64[i + 2] == 0xff &&
	entry_SYSCALL_64[i + 3] == 0x48 &&
	entry_SYSCALL_64[i + 4] == 0x89 &&
	entry_SYSCALL_64[i + 5] == 0xe7) {
      do_syscall_64_offset = *(int *)(entry_SYSCALL_64 + i + 7);
      do_syscall_64 = (unsigned char *)(entry_SYSCALL_64 + i + 11 + do_syscall_64_offset);

      printk(KERN_INFO "call to do_syscall_64 at %p (%p)\n", entry_SYSCALL_64 + i + 6, do_syscall_64);
      break;
    }
  }

  if (!do_syscall_64) {
    printk(KERN_INFO "failed to find do_syscall_64 address\n");
    return 0;
  }
  
  for (i = 0; i < 1024; i++) {
    if (do_syscall_64[i    ] == 0x24 &&
	do_syscall_64[i + 1] == 0x02 &&
	do_syscall_64[i + 2] == 0x00 &&
	do_syscall_64[i + 3] == 0x00 &&
	do_syscall_64[i + 4] == 0x48 &&
	do_syscall_64[i + 5] == 0x19 &&
	do_syscall_64[i + 6] == 0xc0 &&
	do_syscall_64[i + 7] == 0x48 &&
	do_syscall_64[i + 8] == 0x21 &&
	do_syscall_64[i + 9] == 0xc2) {
      sys_call_table_offset = *(int *)(do_syscall_64 + i + 10 + 4);
      sys_call_table = (unsigned long long *)sys_call_table_offset;
      printk(KERN_INFO "call to sys_call_table at %p (%p)\n", do_syscall_64 + i + 10, sys_call_table);
      break;
    }
  }

  if (!sys_call_table) {
    printk(KERN_INFO "failed to find sys_call_table address\n");
    return 0;
  }
  */
  return 0;
}

void cleanup_module(void) {
  printk(KERN_INFO "prime module stopped\n");
}
