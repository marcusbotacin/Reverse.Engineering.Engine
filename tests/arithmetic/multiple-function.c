// test value return

int func()
{
    int a=0;
    return a+2;
}

int func2()
{
    int a=1;
    return a+3;
}

int main()
{
    int a;
    a = func() + func2();
    return 0;
}
