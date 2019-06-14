// test value return

int func(int a,int b)
{
    return a+b+1;
}

int main()
{
    int a,b,c,d,e;
    a=1;
    b=2;
    c=a+b;
    d=a*b;
    e = func(c,d);
    return e;
}
