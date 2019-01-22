# prime\n
\n
pattern in entry_SYSCALL_64 for do_syscall_64\n
\n
e8 ?? ?? ?? ??  callq [offset]\n
\n
v4.9-8\n
4d 31 f6	xor %r14, %r14\n
41 57		push %r15\n
4d 31 ff	xor %r15, %r15\n
48 89 e7	mov %rsp, %rdi\n
\n
v4.17\n
41 57		push %r15\n
45 31 ff	xor %r15d, %r15d\n
48 89 c7	%rax, %rdi\n
48 89 e6	%rsp, %rsi\n
\n
v4.18\n
41 57		push %r15\n
45 31 ff	xor %r15d, %r15d\n
48 89 c7	mov %rax, %rdi\n
48 89 e6	mov %rsp, %rsi\n
\n
v4.19\n
41 57		push %r15\n
45 31 ff	xor %r15d, %r15d\n
48 89 c7	mov %rax, %rdi\n
48 89 e6	mov %rsp, %rsi\n
\n
v4.20\n
41 57		push %r15\n
45 31 ff	xor %r15d, %r15d\n
48 89 c7	mov %rax, %rdi\n
48 89 e6	mov %rsp, %rsi\n
\n
pattern in do_syscall_64 for sys_call_table\n
\n
48 8b 04 d5 ?? ?? ?? ?? mov [offset](, %rax, 8), %rax\n
\n
v4.9-8\n
48 81 fa 24 02 00 00	cmp $0x224, %rdx\n
48 19 c0       	  	sbb %rax, %rax\n
48 21 c2		and %rax, %rax\n
\n
v4.17\n
48 81 ff 4d 01 00 00	cmp $0x14d, %rdi\n
48 19 c0       	  	sbb %rax, %rax\n
48 21 c7		and %rax, %rax\n
\n
v4.18\n
48 81 ff 4f 01 00 00	cmp $0x14f, %rdi\n
48 19 c0       	  	sbb %rax, %rax\n
48 21 c7		and %rax, %rax\n
\n
v4.19\n
48 81 ff 4e 01 00 00	cmp $0x14e, %rdi\n
48 19 c0       	  	sbb %rax, %rax\n
48 21 c7		and %rax, %rax\n
\n
v4.20\n
48 81 ff 4e 01 00 00	cmp $0x14f, %rdi\n
48 19 c0       	  	sbb %rax, %rax\n
48 21 c7		and %rax %rax\n