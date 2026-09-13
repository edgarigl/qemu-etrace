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
	/* Repeat the first eight bytes for ambiguous auto-map tests. */
	.byte	0x90, 0x66, 0x90, 0x0f, 0x1f, 0x40, 0x01, 0x90

	.globl	fallthrough_call_fixture
	.type	fallthrough_call_fixture, @function
fallthrough_call_fixture:
	call	fallthrough_call_target
	.size	fallthrough_call_fixture, .-fallthrough_call_fixture
fallthrough_call_target:
	ret

	.globl	fallthrough_jump_fixture
	.type	fallthrough_jump_fixture, @function
fallthrough_jump_fixture:
	jmp	fallthrough_jump_target
	.size	fallthrough_jump_fixture, .-fallthrough_jump_fixture
fallthrough_jump_target:
	ret

	.globl	fallthrough_conditional_fixture
	.type	fallthrough_conditional_fixture, @function
fallthrough_conditional_fixture:
	jne	fallthrough_conditional_target
	.size	fallthrough_conditional_fixture, .-fallthrough_conditional_fixture
fallthrough_conditional_target:
	ret

	.globl	fallthrough_trap_fixture
	.type	fallthrough_trap_fixture, @function
fallthrough_trap_fixture:
	int3
	.size	fallthrough_trap_fixture, .-fallthrough_trap_fixture
fallthrough_trap_target:
	ret

	.globl	fallthrough_undecodable_fixture
	.type	fallthrough_undecodable_fixture, @function
fallthrough_undecodable_fixture:
	.byte	0x0f
	.size	fallthrough_undecodable_fixture, .-fallthrough_undecodable_fixture
fallthrough_undecodable_target:
	ret
	.section .note.GNU-stack,"",@progbits
