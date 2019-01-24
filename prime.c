#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");

#define ENTRY_SYSCALL_64_SIZE 4032
#define SEARCH_RANGE 512
#define PATTERN_SIZE 7

static void **sys_call_table;
static void **ia32_sys_call_table;

asmlinkage long(*real_close)(int);

asmlinkage long fake_close(int fd) {
  printk(KERN_INFO "sys_close hooked");
  return (*real_close)(fd);
}

void search_sys_call_table(void) {
  int i, j;
  int *do_syscall_64_offset;
  int *sys_call_table_offset;
  int *ia32_sys_call_table_offset;
  unsigned char *entry_SYSCALL_64 = (unsigned char *)(native_load_gs_index - ENTRY_SYSCALL_64_SIZE);
  unsigned char *do_syscall_64;
  unsigned char pattern_0[] = {0x48, 0x89, 0xc7, 0x48, 0x89, 0xe6, 0xe8};
  unsigned char pattern_1[] = {0x48, 0x19, 0xc0, 0x48, 0x21, 0xc7, 0x48};
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
  unsigned char pattern_2[] = {0x00, 0x48, 0x19, 0xd2, 0x21, 0xd0, 0x48};
#else
  unsigned char pattern_2[] = {0xd2, 0x21, 0xd0, 0x48, 0x89, 0xef, 0x48};
#endif
  
  for (i = 0; i < SEARCH_RANGE; i++) {
    for (j = 0; j < PATTERN_SIZE; j++)
      if (entry_SYSCALL_64[i + j] != pattern_0[j])
	break;

    if (j == PATTERN_SIZE) {
      do_syscall_64_offset = (int *)(entry_SYSCALL_64 + i + PATTERN_SIZE);
      do_syscall_64 = (unsigned char *)(entry_SYSCALL_64 + i + PATTERN_SIZE + sizeof(int) + *do_syscall_64_offset);
      printk(KERN_INFO "call to do_syscall_64 at %p (%p)", entry_SYSCALL_64 + i + PATTERN_SIZE - 1, do_syscall_64);
      break;
    } 
  }

  if (!do_syscall_64) {
    printk(KERN_INFO "failed to find do_syscall_64 address");
    return;
  }
  
  for (i = 0; i < SEARCH_RANGE; i++) {
    for (j = 0; j < PATTERN_SIZE; j++)
      if (do_syscall_64[i + j] != pattern_1[j])
	break;
    
    if (j == PATTERN_SIZE) {
      sys_call_table_offset = (int *)(do_syscall_64 + i + PATTERN_SIZE + 3);
      sys_call_table = (void **)(*sys_call_table_offset);
      printk(KERN_INFO "call to sys_call_table at %p (%p)", do_syscall_64 + i + PATTERN_SIZE - 1, sys_call_table); 
      break;
    } 
  }

  for (i = 0; i < SEARCH_RANGE; i++) {
    for (j = 0; j < PATTERN_SIZE; j++)
      if (do_syscall_64[i + j] != pattern_2[j])
	break;

    if (j == PATTERN_SIZE) {
      ia32_sys_call_table_offset = (int *)(do_syscall_64 + i + PATTERN_SIZE + 3);
      ia32_sys_call_table = (void **)(ia32_sys_call_table_offset);
      printk(KERN_INFO "call to ia32_sys_call_table at %p (%p)", do_syscall_64 + i + PATTERN_SIZE - 1, ia32_sys_call_table);
    }
  }

  if (!sys_call_table)
    printk(KERN_INFO "failed to find sys_call_table address");

  if (!ia32_sys_call_table)
    printk(KERN_INFO "failed to find ia32_sys_call_table address");
}

void hook_syscall(void) {
  if (!sys_call_table) {
    printk(KERN_INFO "failed to hook syscall, sys_call_table address is missing");
    return;
  }

  write_cr0(read_cr0() & (~0x10000));
  real_close = (void *)sys_call_table[3];
  sys_call_table[3] = fake_close;
  write_cr0(read_cr0() | 0x10000);
}

void unhook_syscall(void) {
  if (!sys_call_table) {
    printk(KERN_INFO "failed to reset syscall, sys_call_table address is missing");
    return;
  }

  write_cr0(read_cr0() & (~0x10000));
  sys_call_table[3] = real_close;
  write_cr0(read_cr0() | 0x10000);
}

int init_module(void) {
  printk(KERN_INFO "prime module started");
  search_sys_call_table();
  hook_syscall();
  return 0;
}

void cleanup_module(void) {
  printk(KERN_INFO "prime module stopped");
  unhook_syscall();
}
