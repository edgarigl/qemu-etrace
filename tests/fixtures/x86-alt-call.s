	.file	1 "tests/fixtures/x86-alt-call.s"
	.text
	.p2align 4
	.globl	alt_call_fixture
	.type	alt_call_fixture, @function
alt_call_fixture:
	.loc	1 10 0
	nop
	.loc	1 11 0
.Lalt_call_one:
	call	*alt_call_target_ptr(%rip)
	.loc	1 12 0
	ret
	.size	alt_call_fixture, .-alt_call_fixture

	.p2align 4
	.globl	alt_call_pair
	.type	alt_call_pair, @function
alt_call_pair:
	.loc	1 20 0
.Lalt_call_two:
	call	*alt_call_target_ptr(%rip)
	.loc	1 21 0
.Lalt_call_three:
	call	*alt_call_target_ptr(%rip)
	.loc	1 22 0
	ret
	.size	alt_call_pair, .-alt_call_pair

	.p2align 4
	.globl	alt_call_target
	.type	alt_call_target, @function
alt_call_target:
	.byte	0xf3, 0x0f, 0x1e, 0xfa
	ret
	.size	alt_call_target, .-alt_call_target

	.data
	.p2align 3
alt_call_target_ptr:
	.quad	alt_call_target

	.section .init.data,"aw",@progbits
	.globl	__alt_call_sites_start
__alt_call_sites_start:
	.long	.Lalt_call_one - .
	.long	.Lalt_call_two - .
	.long	.Lalt_call_three - .
	.globl	__alt_call_sites_end
__alt_call_sites_end:

	.section .note.GNU-stack,"",@progbits
