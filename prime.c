#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>

#include <linux/vmalloc.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");

#define SEARCH_RANGE 512
#define PATTERN_SIZE 7

static void **sys_call_table;
static void **ia32_sys_call_table;

asmlinkage long(*real_close)(unsigned int);

asmlinkage long fake_close(unsigned int fd) {
  printk(KERN_INFO "sys_close hooked");
  return (*real_close)(fd);
}

static void *khook_map_writable(void *addr, size_t len)
{
  int i;
  void *vaddr = NULL;
  void *paddr = (void *)((unsigned long)addr & PAGE_MASK);
  struct page *pages[DIV_ROUND_UP(offset_in_page(addr) + len, PAGE_SIZE)];

  for (i = 0; i < ARRAY_SIZE(pages); i++, paddr += PAGE_SIZE) {
    if ((pages[i] = __module_address((unsigned long)paddr)
	 ? vmalloc_to_page(paddr)
	 : virt_to_page(paddr)) == NULL)
      return NULL;
  }

  vaddr = vmap(pages, ARRAY_SIZE(pages), VM_MAP, PAGE_KERNEL);
  return vaddr ? vaddr + offset_in_page(addr) : NULL;
}

static void search_sys_call_table(void) {
  int i, j;
  int *do_syscall_64_offset;
  int *sys_call_table_offset;
  int *ia32_sys_call_table_offset;
  unsigned char *entry_SYSCALL_64 = (unsigned char*)native_read_msr(MSR_LSTAR);
  unsigned char *do_syscall_64;
  unsigned char pattern_0[] = {0x48, 0x89, 0xc7, 0x48, 0x89, 0xe6, 0xe8};
  unsigned char pattern_1[] = {0x48, 0x19, 0xc0, 0x48, 0x21, 0xc7, 0x48};
  unsigned char pattern_2[] = {0xd2, 0x21, 0xd0, 0x48, 0x89, 0xef, 0x48};

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

  for ( ; i < SEARCH_RANGE; i++) {
    for (j = 0; j < PATTERN_SIZE; j++)
      if (do_syscall_64[i + j] != pattern_2[j])
	break;

    if (j == PATTERN_SIZE) {
      ia32_sys_call_table_offset = (int *)(do_syscall_64 + i + PATTERN_SIZE + 3);
      ia32_sys_call_table = (void **)(*ia32_sys_call_table_offset);
      printk(KERN_INFO "call to ia32_sys_call_table at %p (%p)", do_syscall_64 + i + PATTERN_SIZE - 1, ia32_sys_call_table);
    }
  }

  if (!sys_call_table)
    printk(KERN_INFO "failed to find sys_call_table address");

  if (!ia32_sys_call_table)
    printk(KERN_INFO "failed to find ia32_sys_call_table address");
}

static void hook_syscall(void) {
  unsigned long long *addr_to_write = (unsigned long long *)khook_map_writable(sys_call_table + __NR_close, 64);
  
  if (!sys_call_table) {
    printk(KERN_INFO "failed to hook syscall64, sys_call_table address is missing");
    return;
  }
  
  real_close = *addr_to_write;
  *addr_to_write = fake_close;
  
  /*
  write_cr0(read_cr0() & ~0x10000);
  real_close = sys_call_table[__NR_close];
  sys_call_table[__NR_close] = fake_close;
  write_cr0(read_cr0() | 0x10000);
  */
}

static void unhook_syscall(void) {
  unsigned long long *addr_to_write = (unsigned long long *)khook_map_writable(sys_call_table + __NR_close, 64);
  
  if (!sys_call_table) {
    printk(KERN_INFO "failed to reset syscall, sys_call_table address is missing");
    return;
  }

  *addr_to_write = real_close;
  
  /*
  write_cr0(read_cr0() & ~0x10000);
  sys_call_table[__NR_close] = real_close;
  write_cr0(read_cr0() | 0x10000);
  */
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
