SECTIONS
{
	. = 0x401000;
	.text : { *(.text .text.*) }
	/DISCARD/ : { *(.discarded) }
}
