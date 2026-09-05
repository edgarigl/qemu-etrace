static inline __attribute__((always_inline)) int inline_helper(int value)
{
	if (value > 0)
		return value + 1;
	return value - 1;
}

static int (*volatile keep_inline_helper)(int) = inline_helper;

__attribute__((noinline)) int call_inline_helper(int value)
{
	return inline_helper(value);
}

int main(void)
{
	return call_inline_helper(1) != 2 || keep_inline_helper == 0;
}
