	.text
	.globl _start
	.type _start,@function
_start:
	mov (%rsp), %rdi
	sub $1, %edi
	call fixture_main
	mov %eax, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start
	/* Match the compiler's external-return-thunk ABI for the fixture. */
	.globl __x86_return_thunk
	.type __x86_return_thunk,@function
__x86_return_thunk:
	ret
	.size __x86_return_thunk, .-__x86_return_thunk
	.section .note.GNU-stack,"",@progbits
