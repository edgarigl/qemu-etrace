	.file	1 "tests/fixtures/assembly-boundary-a.S"
	.text
	.globl	boundary_source
	.type	boundary_source, @function
boundary_source:
	.loc	1 10 0
	nop
	.loc	1 11 0
	jmp	boundary_target
	.loc	1 12 0
	int3
	.size	boundary_source, .-boundary_source

	.file	2 "tests/fixtures/duplicate-assembly.S"
	.local	duplicate_local
	.type	duplicate_local, @function
duplicate_local:
	.loc	2 90 0
	ret
	.size	duplicate_local, .-duplicate_local

	.section .note.GNU-stack,"",@progbits
