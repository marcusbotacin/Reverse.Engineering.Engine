// test value return

int func(int a)
{
    if(a>0)
    {
        return 0;
    }else{
        return -1;
    }
}

int main()
{
    int a;
    a = func(10);
    a = func(0);
    return 0;
}
