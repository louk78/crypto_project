#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "bignum.h"

char *stra = "1221323213871983878";
char *strb = "9821231821382178271832173765453";

int main()
{
    bignum *a, *b, *c, *d, *e;
    char *resulta, *resultb;
    a = bignum_alloc();
    b = bignum_alloc();
    c = bignum_alloc();
    d = bignum_alloc();
    e = bignum_alloc();

    bignum_fromstring(a, stra);
    bignum_fromstring(b, strb);
    resulta = bignum_tostring(a);
    resultb = bignum_tostring(b);
    puts(resultb);
    puts(resulta);
    free(resulta);
    free(resultb);

    bignum_multiply(c, a, b);
    puts(bignum_tostring(c));

    bignum_subtract(c, a, b);
    puts(bignum_tostring(c));

    bignum_divide(d, e, a, b);

    printf("quotient=%s\n", bignum_tostring(d));
    printf("remainder=%s\n", bignum_tostring(e));

    bignum_free(a);
    bignum_free(b);
    return 0;
}
