#ifndef CALLER
#error CALLER must name the exported caller
#endif

#ifndef KEEP
#error KEEP must name the retained function pointer
#endif

static inline __attribute__((always_inline)) int shared_inline_helper(int value)
{
	if (value > 0)
		return value + 1;
	return value - 1;
}

static int (*volatile KEEP)(int) = shared_inline_helper;

__attribute__((noinline)) int CALLER(int value)
{
	return shared_inline_helper(value) + (KEEP == 0);
}
