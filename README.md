# prime

Linux kernel rootkit for kernel version 4.[17-20]

### Looking for entry_SYSCALL_64 address

EXPORT_SYMBOL(native_load_gs_index) in arch/x86/entry/entry_64.S  
Offset between entry_SYSCALL_64 and native_load_gs_index : 3408 bytes  

### Looking for call to do_syscall_64 in entry_SYSCALL_64 (arch/x86/entry/entry_64.S)
```
e8 ?? ?? ?? ??  callq [offset]
```

pattern detection
```
48 89 c7    mov %rax, %rdi  
48 89 e6    mov %rsp, %rsi  
```
### Looking for sys_call_table offset in do_syscall_64 (arch/x86/entry/common.c)
```
48 8b 04 fd ?? ?? ?? ?? mov [offset](, %rdi, 8), %rax
```

pattern detection
```
48 19 c0    sbb %rax, %rax  
48 21 c7    and %rax, %rax  
```

### Looking for ia32_sys_call_table offset in do_syscall_32_irqs_on (arch/x86/entry/common.c)
```
48 8b 04 c5 ?? ?? ?? ?? move [offset](, %rax, 8), %rax
```

pattern detection
```
v4.17  
48 19 d2    sbb %rdx, %rdx  
21 d0       and %edx, %eax  
v4.[18-20]  
48 19 d2    sbb %rdx, %rdx  
21 d0       and %edx, %eax  
48 89 ef    mov %rbp, %rdi  
```

### References
https://github.com/torvalds/linux/blob/master/arch/x86/entry/entry_64.S  
https://github.com/torvalds/linux/blob/master/arch/x86/entry/common.c  
https://0xax.gitbooks.io/linux-insides/content/SysCall/linux-syscall-1.html  
