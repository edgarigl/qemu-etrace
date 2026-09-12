struct Worker
{
    int run(int value);
};

__attribute__((noinline))
int Worker::run(int value)
{
    return value + 1;
}

int main()
{
    Worker worker;

    return worker.run(1);
}
