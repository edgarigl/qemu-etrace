volatile int return_values[4] = { 1, 2, 3, 4 };

__attribute__((noinline, noipa)) int single_return(int kind, int n)
{
    int value;

    switch (kind) {
    case 1:
        value = return_values[0];
        break;
    case 2:
        value = 0;
        for (int i = 0; i < n; i++)
            value += return_values[i & 3];
        break;
    default:
        value = 7;
        break;
    }
    return value;
}

__attribute__((noinline, noipa)) int folded_returns(int x)
{
    if (x)
        return x + 2;
    return x + 2;
}

__attribute__((noinline, noipa)) int branchless_returns(int x)
{
    if (x)
        return 1;
    return 0;
}

int fixture_main(int x)
{
    return single_return(x, 3) + folded_returns(x) + branchless_returns(x);
}
