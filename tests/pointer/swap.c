void swap(int *p, int *q)
{
   int tmp;
   tmp = *p;
   *p = *q; 
   *q = tmp;
}

int main()
{
    int a = 1;
    int b = 2;
    swap(&a,&b);
    return a;
}

