// test value return

int func(int* p)
{
    *p=0;
}

int main()
{
    int a;
    a = 1;
    func(&a);
    return a;
}
