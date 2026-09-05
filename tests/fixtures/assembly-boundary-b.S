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

	.globl	repeated_line
	.type	repeated_line, @function
repeated_line:
	.loc	1 70 0 discriminator 1
	nop
	.loc	1 70 0 discriminator 2
	nop
	ret
	.size	repeated_line, .-repeated_line

	.file	2 "tests/fixtures/duplicate-assembly.S"
	.local	duplicate_local
	.type	duplicate_local, @function
duplicate_local:
	.loc	2 91 0
	ret
	.size	duplicate_local, .-duplicate_local

	.globl	zero_sized_entry
zero_sized_entry:
	.loc	1 40 0
	nop
	ret

	.globl	zero_sized_function
	.type	zero_sized_function, @function
zero_sized_function:
	.loc	1 45 0
	nop
	ret

	.globl	zero_sized_alias_one
	.type	zero_sized_alias_one, @function
	.globl	zero_sized_alias_two
	.type	zero_sized_alias_two, @function
zero_sized_alias_one:
zero_sized_alias_two:
	.loc	1 47 0
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

	.section .text.tail,"ax",@progbits
	.globl	same_cu_restart
	.type	same_cu_restart, @function
same_cu_restart:
	.loc	1 80 0
	ret
	.size	same_cu_restart, .-same_cu_restart

	.globl	_aliased_entry
	.local	aliased_function
	.type	aliased_function, @function
_aliased_entry:
aliased_function:
	.loc	1 85 0
	nop
	ret
	.size	aliased_function, .-aliased_function

	.section .note.GNU-stack,"",@progbits
