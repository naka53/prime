# prime

Linux kernel rootkit for kernel version 4.[17-20]

### Looking for entry_SYSCALL_64 address  
```
4.17 (arch/x86/entry/entry_64.S)  
EXPORT_SYMBOL(native_load_gs_index)  
offset between entry_SYSCALL_64 and native_load_gs_index : 3392  

4.18 (arch/x86/entry/entry_64.S)  
EXPORT_SYMBOL(native_load_gs_index)  
offset between entry_SYSCALL_64 and native_load_gs_index : 3392  

4.19 (arch/x86/entry/entry_64.S)  
EXPORT_SYMBOL(native_load_gs_index)  
offset between entry_SYSCALL_64 and native_load_gs_index : 3392  

4.20 (arch/x86/kernel/cpu/common.c)  
wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);
```

### Looking for call to do_syscall_64 in entry_SYSCALL_64 (arch/x86/entry/entry_64.S)
```
e8 ?? ?? ?? ??  callq [offset]
```

pattern detection
```
4.17  
41 57                 push %r15  
45 31 ff              xor %r15d, %r15d  
48 89 c7              mov %rax, %rdi  
48 89 e6              mov %rsp, %rsi  

4.18  
41 57                 push %r15  
45 31 ff              xor %r15d, %r15d  
48 89 c7              mov %rax, %rdi  
48 89 e6              mov %rsp, %rsi  

4.19  
41 57                 push %r15  
45 31 ff              xor %r15d, %r15d  
48 89 c7              mov %rax, %rdi  
48 89 e6              mov %rsp, %rsi  

4.20  
41 57                 push %r15  
45 31 ff              xor %r15d, %r15d  
48 89 c7              mov %rax, %rdi  
48 89 e6              mov %rsp, %rsi  
```
### Looking for sys_call_table offset in do_syscall_64 (arch/x86/entry/common.c)
```
48 8b 04 fd ?? ?? ?? ?? mov [offset](, %rdi, 8), %rax
```

pattern detection
```
4.17  
48 81 ff 4d 01 00 00  cmp $0x14d, %rdi  
48 19 c0              sbb %rax, %rax  
48 21 c7              and %rax, %rdi  

4.18  
48 81 ff 4f 01 00 00  cmp $0x14f, %rdi  
48 19 c0              sbb %rax, %rax  
48 21 c7              and %rax, %rdi  

4.19  
48 81 ff 4f 01 00 00  cmp $0x14f, %rdi  
48 19 c0              sbb %rax, %rax  
48 21 c7              and %rax, %rdi  

4.20  
48 81 ff 4f 01 00 00  cmp $0x14f, %rdi  
48 19 c0              sbb %rax, %rax  
48 21 c7              and %rax, %rdi  
```

### Looking for ia32_sys_call_table offset in do_syscall_32_irqs_on (arch/x86/entry/common.c)
```
48 8b 04 c5 ?? ?? ?? ?? move [offset](, %rax, 8), %rax
```

pattern detection
```
4.17  
48 81 fa 81 01 00 00  cmp $0x181, %rdx  
48 19 d2              sbb %rdx, %rdx  
21 d0                 and %edx, %eax  

4.18  
48 81 fa 83 01 00 00  cmp $0x183, %rdx  
48 19 d2              sbb %rdx, %rdx  
21 d0                 and %edx, %eax  
48 89 ef              mov %rbp, %rdi  

4.19  
48 81 fa 83 01 00 00  cmp $0x183, %rdx  
48 19 d2              sbb %rdx, %rdx  
21 d0                 and %edx, %eax  
48 89 ef              mov %rbp, %rdi  

4.20  
48 81 fa 83 01 00 00  cmp $0x182, %eax  
48 19 d2              sbb %rdx, %rdx  
21 d0                 and %edx, %eax  
48 89 ef              mov %rbp, %rdi  
```

### References
https://0xax.gitbooks.io/linux-insides/content/SysCall/  
https://github.com/torvalds/linux/blob/master/arch/x86/kernel/cpu/common.c  
https://github.com/torvalds/linux/blob/master/arch/x86/entry/entry_64.S  
https://github.com/torvalds/linux/blob/master/arch/x86/entry/common.c  
https://github.com/torvalds/linux/commit/2ca2a09d6215fd9621aa3e2db7cc9428a61f2911#diff-acc7893dfa77092a11e1b53e98a34d44  
https://github.com/torvalds/linux/commit/bf904d2762ee6fc1e4acfcb0772bbfb4a27ad8a6#diff-ebc0521fec74b465090151aabc564493  
