#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

#define ENTRY_SYSCALL_64_SIZE 4096
#define PATTERN_0_SIZE 6
#define PATTERN_1_SIZE 6

int init_module(void) {
  int i, j;
  bool found;
  int do_syscall_64_offset;
  int sys_call_table_offset;
  unsigned char *do_syscall_64;
  unsigned long long *sys_call_table;
  unsigned char *entry_SYSCALL_64 = (unsigned char*)(native_load_gs_index - ENTRY_SYSCALL_64_SIZE);
  unsigned char pattern_0[] = {0x48, 0x89, 0xc7, 0x48, 0x89, 0xe6};
  unsigned char pattern_1[] = {0x48, 0x19, 0xc0, 0x48, 0x21, 0xc2};
  
  printk(KERN_INFO "prime module started\n");

  for (i = 0; i < 1024; i++) {
    found = true;
    for (j = 0; i < PATTERN_0_SIZE; j++) {
      if (entry_SYSCALL_64[i + j] != pattern_0[j]) {
	found = false;
	break;
      }
    }

    if (found) {
      do_syscall_64_offset = *(int *)(entry_SYSCALL_64 + i + 6 + 1);
      do_syscall_64 = (unsigned char *)(entry_SYSCALL_64 + i + 6 + 1 + 4 + do_syscall_64_offset);
      printk(KERN_INFO "call to do_syscall_64 at %p (%p)", entry_SYSCALL_64 + i + 9, do_syscall_64);
      break;
    } 
  }

  if (!do_syscall_64) {
    printk(KERN_INFO "failed to find do_syscall_64 address\n");
    return 1;
  }
  
  for (i = 0; i < 1024; i++) {
    found = true;
    for (j = 0; i < PATTERN_1_SIZE; j++) {
      if (do_syscall_64[i + j] != pattern_1[j]) {
	found = false;
	break;
      }
    }

    if (found) {
      sys_call_table_offset = *(int *)(do_syscall_64 + i + 6 + 4);
      sys_call_table = (unsigned long long *)sys_call_table_offset;
      printk(KERN_INFO "call to sys_call_table at %p (%p)", do_syscall_64 + i + 6, sys_call_table); 
      break;
    } 
  }

  if (!do_syscall_64) {
    printk(KERN_INFO "failed to find do_syscall_64 address\n");
    return 1;
  }

  
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
    return 1;
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
    return 1;
  }
  */
  return 0;
}

void cleanup_module(void) {
  printk(KERN_INFO "prime module stopped\n");
}
