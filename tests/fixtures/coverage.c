static __attribute__((noinline)) int covered(int value)
{
	return value + 1;
}

static __attribute__((noinline)) int uncovered(int value)
{
	if (value > 0)
		return value - 1;
	return value;
}

int main(void)
{
	return covered(0) + uncovered(0);
}
