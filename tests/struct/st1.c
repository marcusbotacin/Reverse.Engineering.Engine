#include<stdio.h>

typedef struct {
    int a, b, c; 
} data;

int main (void) {
    printf ("%ld\n", sizeof (data));
    return 0;
}
