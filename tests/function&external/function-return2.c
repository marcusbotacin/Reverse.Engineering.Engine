// test value return

int func()
{
    int a=1;
    return a;
}

int main()
{
    int b,c;
    b = func();
    c = func();
    return b+c;
}
