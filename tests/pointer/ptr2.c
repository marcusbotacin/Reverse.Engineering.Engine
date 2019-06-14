int main()
{
    int a;
    int b;
    int *p=&a;
    *p=1;
    p=&b;
    *p=2;
    return a+b;
}
