// test value return

int a=5;

void func()
{
    a+=1;
}

int main()
{
    int b=1;
    func();
    func();
    func();
    return a+b;
}
