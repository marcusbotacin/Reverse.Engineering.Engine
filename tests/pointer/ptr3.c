int main()
{
    int a=1;
    int b=2;
    int c;
    int *p; 
    int *q; 
    p = &a;
    q = &b;  
    c = *p + *q;
    return c;
}
