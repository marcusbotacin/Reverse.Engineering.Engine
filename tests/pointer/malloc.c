#include<stdlib.h>
int main()
{
    int *p = malloc(20);
    p[0] = 10;
    return p[0];
}
