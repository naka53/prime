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
48 8b 04 d5 ?? ?? ?? ?? mov [offset](, %rax, 8), %rax
```

pattern detection
```
48 19 c0    sbb %rax, %rax  
48 21 c7    and %rax, %rax  
```
