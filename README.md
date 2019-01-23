# prime

pattern in entry_SYSCALL_64 before do_syscall_64

e8 ?? ?? ?? ??  callq [offset]


v4.[17-20]  
41 57		    push %r15  
45 31 ff	  xor %r15d, %r15d  
48 89 c7	  mov %rax, %rdi  
48 89 e6	  mov %rsp, %rsi  

pattern in do_syscall_64 before sys_call_table

48 8b 04 d5 ?? ?? ?? ?? mov [offset](, %rax, 8), %rax

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

Offset between entry_SYSCALL_64 and native_load_gs_index

v4.[17-20]
3408
