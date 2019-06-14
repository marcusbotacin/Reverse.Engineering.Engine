// test value return

int fat(int n)
{   
    if(n==0)
    {
        return 1;
    }else{
        return n*fat(n-1);
    }
}


int main()
{
    int a;
    a = fat(5);
    return 0;
}
