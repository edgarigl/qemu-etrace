	.file 1 "tests/fixtures/attribution.c"
	.text
	.globl attribution_sample
	.type attribution_sample, @function
attribution_sample:
	/* Retain two source coordinates at the same machine address. */
	.loc 1 10 3 is_stmt 1 discriminator 7
	.loc 1 10 11 is_stmt 0 discriminator 8
	nop
	nop
	nop
	.loc 1 20 5 is_stmt 1
	ret
	.size attribution_sample, .-attribution_sample

	/* Discarded code retains line evidence but cannot supply image hits. */
	.section .discarded,"ax",@progbits
	.loc 1 99 0 is_stmt 0
	nop
	.section .note.GNU-stack,"",@progbits
