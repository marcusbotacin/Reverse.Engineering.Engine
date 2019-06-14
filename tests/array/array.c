#include<stdio.h>

#define N 2

int main()
{
    int i;
    int array[N];
    array[0]=1;
    for(i=1;i<N;i++)
    {
        array[i]=array[i-1]+1;
    }
    return array[N-1];
}
