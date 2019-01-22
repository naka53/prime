#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

#define ENTRY_SYSCALL_64_SIZE 4096
#define SEARCH_RANGE 1024
#define PATTERN_0_SIZE 6
#define PATTERN_1_SIZE 6

int init_module(void) {
  int i, j;
  bool patter_found;
  int *do_syscall_64_offset;
  int *sys_call_table_offset;
  unsigned char *entry_SYSCALL_64 = (unsigned char *)(native_load_gs_index - ENTRY_SYSCALL_64_SIZE);
  unsigned char *do_syscall_64;
  unsigned long long *sys_call_table;
  unsigned char pattern_0[] = {0x48, 0x89, 0xc7, 0x48, 0x89, 0xe6};
  unsigned char pattern_1[] = {0x48, 0x19, 0xc0, 0x48, 0x21, 0xc7};
  
  printk(KERN_INFO "prime module started");

  for (i = 0; i < SEARCH_RANGE; i++) {
    pattern_found = true;
    for (j = 0; j < PATTERN_0_SIZE; j++) {
      if (entry_SYSCALL_64[i + j] != pattern_0[j]) {
	patter_found = false;
	break;
      }
    }

    if (pattern_found) {
      do_syscall_64_offset = (int *)(entry_SYSCALL_64 + i + PATTERN_0_SIZE + 1);
      do_syscall_64 = (unsigned char *)(entry_SYSCALL_64 + i + PATTERN_0_SIZE + 1 + 4 + *do_syscall_64_offset);
      printk(KERN_INFO "call to do_syscall_64 at %p (%p)", entry_SYSCALL_64 + i + PATTERN_0_SIZE, do_syscall_64);
      break;
    } 
  }

  if (!do_syscall_64) {
    printk(KERN_INFO "failed to find do_syscall_64 address");
    return 1;
  }

  
  for (i = 0; i < SEARCH_RANGE; i++) {
    pattern_found = true;
    for (j = 0; j < PATTERN_1_SIZE; j++) {
      if (do_syscall_64[i + j] != pattern_1[j]) {
	pattern_found = false;
	break;
      }
    }

    if (pattern_found) {
      sys_call_table_offset = (int *)(do_syscall_64 + i + PATTERN_1_SIZE + 4);
      sys_call_table = (unsigned long long *)(*sys_call_table_offset);
      printk(KERN_INFO "call to sys_call_table at %p (%p)", do_syscall_64 + i + PATTERN_1_SIZE, sys_call_table); 
      break;
    } 
  }

  if (!sys_call_table) {
    printk(KERN_INFO "failed to find sys_call_table address");
    return 1;
  }
  
  return 0;
}

void cleanup_module(void) {
  printk(KERN_INFO "prime module stopped");
}
