#include<stdio.h>

typedef struct {
    int a, b, c; 
} data;

int main (void) {
    data d;
    d.a=1;
    d.b=2;
    d.c=d.a+d.b;
    printf ("%d\n", d.c);
    return 0;
}
