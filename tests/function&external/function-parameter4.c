// test value return

int func2(int a,int b)
{
    return a*b;
}

int func(int a,int b)
{
    return a+b;
}

int main()
{
    int a,b;
    a = func(1,2);
    b = func2(1,2);
    return a+b;
}
