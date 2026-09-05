SECTIONS
{
	. = 0x401000;
	.text : { *(.text) }
	/DISCARD/ : { *(.discarded) }
}
