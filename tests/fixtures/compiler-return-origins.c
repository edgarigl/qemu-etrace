/* Source-origin counterexamples, compiled without coverage instrumentation. */
#define NOIPA __attribute__((noinline, noipa))
#define RETURN_VALUE(value) return (value)

NOIPA int terminal_return(int x)
{
    int value = x + 1;
    return value;
}

NOIPA int folded_origins(int x)
{
    if (x)
        return x + 2;
    return x + 2;
}

NOIPA int branchless_origins(int x)
{
    if (x)
        return 1;
    return 0;
}

NOIPA int macro_origins(int x)
{
    if (x)
        RETURN_VALUE(1);
    return 0;
}

NOIPA void explicit_and_implicit(int x)
{
    if (x)
        return;
}

NOIPA int discarded_fallthrough(int x)
{
    if (x)
        return 1;
    /* Reaching the end is defined when the caller discards the value. */
}

NOIPA int constant_dead_return(int x)
{
    if (0)
        return 1;
    return x;
}

NOIPA int same_line_origins(int x)
{
    if (x) return 1; else return 0;
}

int fixture_main(int x)
{
    explicit_and_implicit(x);
    (void)discarded_fallthrough(x);
    return terminal_return(x) + folded_origins(x) + branchless_origins(x)
        + macro_origins(x) + constant_dead_return(x) + same_line_origins(x);
}
