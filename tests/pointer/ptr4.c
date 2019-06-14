int main()
{
    int a=1;
    int b=2;
    int c;
    int *p,*q,*r,*s,*t; 
    p = &a;
    q = &b;
    r = &a;
    s = &b;
    t = &a;  
    c = *p + *q + *r + *s + *t;
    return c;
}
