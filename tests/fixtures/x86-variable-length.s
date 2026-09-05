	.file	1 "tests/fixtures/x86-variable-length.s"
	.text
	.p2align 4
	.byte	0x90
	.globl	x86_coverage_fixture
	.type	x86_coverage_fixture, @function
x86_coverage_fixture:
	.loc	1 10 0
	nop
	.loc	1 11 0
	xchg	%ax, %ax
	.loc	1 12 0
	nopl	1(%rax)
	.loc	1 13 0
	nop
	.loc	1 14 0
	xchg	%ax, %ax
	.loc	1 15 0
	ret
	.size	x86_coverage_fixture, .-x86_coverage_fixture
	.section .note.GNU-stack,"",@progbits
