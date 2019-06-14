// test value return

int d=1;

int func()
{
    int a=1;
    return a+d;
}

int main()
{
    int b,c;
    b = func();
    c = func();
    return b+c;
}
