int call_inline_helper_a(int value);
int call_inline_helper_b(int value);

int main(void)
{
	return call_inline_helper_a(1) + call_inline_helper_b(1) != 4;
}
