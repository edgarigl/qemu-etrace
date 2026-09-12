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

	.p2align 4
	.globl	alt_empty_fixture
	.type	alt_empty_fixture, @function
alt_empty_fixture:
	.loc	1 60 0
	lock addq $1, alt_counter(%rip)
	.loc	1 61 0
.Lalt_empty:
	.byte	0x0f, 0xae, 0xe8
	.loc	1 62 0
	lock addq $1, alt_counter(%rip)
	.loc	1 63 0
	mov	%rax, %rdx
	.loc	1 64 0
	ret
	.size	alt_empty_fixture, .-alt_empty_fixture

	.p2align 4
	.globl	alt_empty_long_fixture
	.type	alt_empty_long_fixture, @function
alt_empty_long_fixture:
	.loc	1 70 0
.Lalt_empty_long:
	mov	$1, %eax
	.loc	1 71 0
	ret
	.size	alt_empty_long_fixture, .-alt_empty_long_fixture

	.p2align 4
	.globl	alt_unregistered_fixture
	.type	alt_unregistered_fixture, @function
alt_unregistered_fixture:
	.loc	1 80 0
	nop
	.loc	1 81 0
.Lalt_unregistered:
	.byte	0x0f, 0xae, 0xe8
	.loc	1 82 0
	ret
	.size	alt_unregistered_fixture, .-alt_unregistered_fixture

	.p2align 4
	.globl	alt_padding_fixture
	.type	alt_padding_fixture, @function
alt_padding_fixture:
	.loc	1 90 0
	lock addq $1, alt_counter(%rip)
	.loc	1 91 0
.Lalt_padding:
	.byte	0x0f, 0x1f, 0x00
	.loc	1 92 0
	lock addq $1, alt_counter(%rip)
	.loc	1 93 0
	ret
	.size	alt_padding_fixture, .-alt_padding_fixture

	.p2align 4
	.globl	alt_padding_original_fixture
	.type	alt_padding_original_fixture, @function
alt_padding_original_fixture:
	.loc	1 100 0
.Lalt_padding_original:
	.byte	0x90
	.loc	1 101 0
	.byte	0x66, 0x90
	.loc	1 102 0
	ret
	.size	alt_padding_original_fixture, .-alt_padding_original_fixture

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

	.section .altinstr_replacement,"ax",@progbits
.Lalt_empty_replacement:
.Lalt_empty_long_replacement:
	.byte	0xcc
.Lalt_padding_replacement:
	.byte	0x0f, 0x01, 0xcb
.Lalt_padding_original_replacement:
	.byte	0x0f, 0x01, 0xcb

	.section .altinstructions,"aw",@progbits
	.globl	__alt_instructions
__alt_instructions:
	.long	.Lalt_empty - .
	.long	.Lalt_empty_replacement - .
	.word	0x026c
	.byte	3
	.byte	0
	.byte	0
	.byte	0
	.long	.Lalt_empty_long - .
	.long	.Lalt_empty_long_replacement - .
	.word	0x026c
	.byte	5
	.byte	0
	.byte	0
	.byte	0
	.long	.Lalt_padding - .
	.long	.Lalt_padding_replacement - .
	.word	0x026b
	.byte	0
	.byte	3
	.byte	3
	.byte	0
	.long	.Lalt_padding_original - .
	.long	.Lalt_padding_original_replacement - .
	.word	0x026b
	.byte	1
	.byte	3
	.byte	2
	.byte	0
	.globl	__alt_instructions_end
__alt_instructions_end:

	.data
	.p2align 3
alt_counter:
	.quad	0

	.section .note.GNU-stack,"",@progbits
