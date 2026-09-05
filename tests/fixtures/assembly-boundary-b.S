	.file	1 "tests/fixtures/assembly-boundary-b.S"
	.text
	.globl	boundary_target
	.type	boundary_target, @function
boundary_target:
	nop
	.loc	1 20 0
	ret
	.size	boundary_target, .-boundary_target

	.loc	1 30 0
	.macro	DEFINE_THUNK name
	.globl	\name
	.type	\name, @function
\name:
	nop
	ret
	.size	\name, .-\name
	.endm

	DEFINE_THUNK macro_thunk_one
	DEFINE_THUNK macro_thunk_two
	DEFINE_THUNK macro_thunk_three

	.globl	zero_sized_entry
zero_sized_entry:
	.loc	1 40 0
	nop
	ret

	.globl	after_zero_sized
	.type	after_zero_sized, @function
after_zero_sized:
	.loc	1 50 0
	ret
	.size	after_zero_sized, .-after_zero_sized

	.section .discarded,"ax",@progbits
	.globl	discarded_function
	.type	discarded_function, @function
discarded_function:
	.loc	1 60 0
	ret
	.size	discarded_function, .-discarded_function

	.section .note.GNU-stack,"",@progbits
