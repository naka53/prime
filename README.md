# prime

pattern in entry_SYSCALL_64 for do_syscall_64

e8 ?? ?? ?? ??  callq [offset]

v4.9-8  
4d 31 f6	  xor %r14, %r14  
41 57		    push %r15  
4d 31 ff	  xor %r15, %r15  
48 89 e7	  mov %rsp, %rdi  

v4.17  
41 57		    push %r15  
45 31 ff	  xor %r15d, %r15d  
48 89 c7	  mov %rax, %rdi  
48 89 e6	  mov %rsp, %rsi  

v4.18  
41 57		    push %r15  
45 31 ff	  xor %r15d, %r15d  
48 89 c7	  mov %rax, %rdi  
48 89 e6	  mov %rsp, %rsi  

v4.19  
41 57		    push %r15  
45 31 ff	  xor %r15d, %r15d  
48 89 c7	  mov %rax, %rdi  
48 89 e6	  mov %rsp, %rsi  

v4.20  
41 57		    push %r15  
45 31 ff	  xor %r15d, %r15d  
48 89 c7	  mov %rax, %rdi  
48 89 e6	  mov %rsp, %rsi  

pattern in do_syscall_64 for sys_call_table

48 8b 04 d5 ?? ?? ?? ?? mov [offset](, %rax, 8), %rax

v4.9-8  
48 81 fa 24 02 00 00	cmp $0x224, %rdx  
48 19 c0       	  	  sbb %rax, %rax  
48 21 c2		          and %rax, %rax  

v4.17  
48 81 ff 4d 01 00 00	cmp $0x14d, %rdi  
48 19 c0       	  	  sbb %rax, %rax  
48 21 c7		          and %rax, %rax  

v4.18  
48 81 ff 4f 01 00 00	cmp $0x14f, %rdi  
48 19 c0       	  	   sbb %rax, %rax  
48 21 c7		            and %rax, %rax  

v4.19  
48 81 ff 4e 01 00 00	cmp $0x14e, %rdi  
48 19 c0       	  	  sbb %rax, %rax  
48 21 c7		          and %rax, %rax  

v4.20
48 81 ff 4e 01 00 00	cmp $0x14f, %rdi  
48 19 c0       	  	  sbb %rax, %rax  
48 21 c7		          and %rax %rax  
