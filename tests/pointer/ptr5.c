int main()
{
    int a;
    int *p=&a;
    int **q=&p;
    **q=1;
    return a;
}
