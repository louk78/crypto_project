#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <assert.h>

#include "rsa.h"
#include "bignum.h"

#define PRIMALITY_TEST_REPEAT 100
#define EXPONENT_MAX RAND_MAX

static void gcd(bignum *b1, bignum *b2, bignum *result);
static void random_exponent(bignum *phi, uint32_t upper, bignum *result);
static void bignum_pow_mod(bignum *result, bignum *base, bignum *expo, bignum *mod);
static int miller_rabin_test(bignum *n, int repeat);
static void random_prime(int digits, bignum *result);
void randPrime(int numDigits, bignum* result);


static void print_bignum(char *s, bignum *b)
{
    char *k;
    k = bignum_tostring(b);
    printf("%s = %s\n", s, k);
    free(k);
}

static void gcd(bignum *b1, bignum *b2, bignum *result)
{
    bignum *a = bignum_alloc(), *b = bignum_alloc();
    bignum *temp = bignum_alloc();
    bignum_copy(b1, a);
	bignum_copy(b2, b);
    while(!bignum_iszero(b))
    {
		bignum_copy(b, temp);
		bignum_imod(a, b);
		bignum_copy(a, b);
		bignum_copy(temp, a);
	}
    bignum_copy(a, result);
}

/*
void xgcd(bignum* a, bignum* mod, bignum* result)
{
	bignum *remprev = bignum_alloc(), *rem = bignum_alloc();
	bignum *auxprev = bignum_alloc(), *aux = bignum_alloc();
	bignum *rcur = bignum_alloc(), *qcur = bignum_alloc(), *acur = bignum_alloc();
    bignum *one = bignum_alloc();
    bignum_fromint(one, 1);

	bignum_copy(mod, remprev);
	bignum_copy(a, rem);
	bignum_fromint(auxprev, 0);
	bignum_fromint(aux, 1);
	while(bignum_isgreater(rem, one))
    {
		bignum_divide(qcur, rcur, remprev, rem);
		bignum_subtract(acur, mod, qcur);
		bignum_imultiply(acur, aux);
		bignum_iadd(acur, auxprev);
		bignum_imod(acur, mod);

		bignum_copy(rem, remprev);
		bignum_copy(aux, auxprev);
		bignum_copy(rcur, rem);
		bignum_copy(acur, aux);
	}

	bignum_copy(acur, result);

	bignum_free(remprev); bignum_free(rem); bignum_free(auxprev);
	bignum_free(aux); bignum_free(rcur); bignum_free(qcur);
	bignum_free(acur); bignum_free(one);
}
*/

//modified extended Euclidean algorithm from Knuth [KNU298, Vol 2 Algorithm X p 342]
//avoiding negative integers.
void modular_inverse(bignum* a, bignum* mod, bignum* result)
{
    bignum *u1 = bignum_alloc();
    bignum *u3 = bignum_alloc();
    bignum *v1 = bignum_alloc();
    bignum *v3 = bignum_alloc();
    bignum *t1 = bignum_alloc();
    bignum *t3 = bignum_alloc();
    bignum *q = bignum_alloc();

    int iter=1;
    bignum_fromint(u1, 1);
    bignum_copy(a, u3);
    bignum_copy(mod, v3);

    while (!bignum_iszero(v3))
    {
        bignum_divide(q, t3, u3, v3);
        bignum_imultiply(q, v1);
        bignum_add(t1, u1, q);

        bignum_copy(v1, u1);
        bignum_copy(t1, v1);
        bignum_copy(v3, u3);
        bignum_copy(t3, v3);

        iter = -iter;
    }
    if (iter < 0)
        bignum_subtract(result, mod, u1);
    else
        bignum_copy(u1, result);
    bignum_free(t1);
    bignum_free(u1);
    bignum_free(v1);
    bignum_free(v3);
    bignum_free(t3);
    bignum_free(u3);
    bignum_free(q);
}


//find result < upper such that gcd(result, phi)==1
static void random_exponent(bignum *phi, uint32_t upper, bignum *result)
{
    bignum* x = bignum_alloc();
    uint32_t e;
    e = rand() % upper;
    while(1)
    {
        // printf("ee = %u\n", e);
        bignum_fromint(result, e);
        gcd(result, phi, x);
        // print_bignum("gcd", x);
        if(x->length == 1 && x->data[0] == 1)
        {
            //break when gcd==1
            break;
        }
        //try next number
        e = (e+1) % upper;
        if(e < 3)
            e = 3;
    }
    bignum_free(x);
}

//result = base^exp % mod
static void bignum_pow_mod(bignum* result, bignum* base, bignum* expo, bignum* mod)
{
	bignum *a = bignum_alloc(), *b = bignum_alloc();
	bignum *tmp = bignum_alloc();

	bignum_copy(base, a);
	bignum_copy(expo, b);
	bignum_fromint(result, 1);

	while(!bignum_iszero(b))
    {
		if(b->data[0] & 1)
        {
			bignum_imultiply(result, a);
			bignum_imod(result, mod);
		}
		bignum_idivide_2(b);
		bignum_copy(a, tmp);
		bignum_imultiply(a, tmp);
		bignum_imod(a, mod);
	}
	bignum_free(a);
	bignum_free(b);
	bignum_free(tmp);
}

static int miller_rabin_test(bignum *n, int repeat)
{
    bignum *n_1 = bignum_alloc();
    bignum *a = bignum_alloc();
    bignum *q = bignum_alloc();
    bignum *one = bignum_alloc();
    bignum *x = bignum_alloc();
    uint32_t k = 0;
    uint32_t i;
    int result = 1;

    one->length = 1;
    one->data[0] = 1;

    bignum_subtract(n_1, n, one);
    bignum_copy(n_1, q);
    //n-1 = 2^k x q
    while(!bignum_isodd(q))
    {
        bignum_idivide_2(q);
        k++;
    }

    while(repeat--)
    {
        bignum_random(10*n_1->length, a);
        bignum_imod(a, n_1);
        bignum_pow_mod(x, a, q, n);
        if (bignum_isequal(x, one))
            continue;   //a is not well chosen
        i = 0;
        while(!bignum_isequal(x, n_1))
        {
            // printf("i=%u\n", i);
            if(i == (k-1))
            {
                result = 0;
                goto test_done;
            }
            else
            {
                i++;
                bignum_imultiply(x, x);
                bignum_imod(x, n);
            }
        }
    }

test_done:
    bignum_free(a);
    bignum_free(q);
    bignum_free(n_1);
    bignum_free(x);
    bignum_free(one);
    return result;
}

static void random_prime(int bytes, bignum *result)
{
    bignum_random(bytes, result);
    if(!bignum_isodd(result))
        result->data[0] += 1;
    while(1)
    {
        printf(".");
        fflush(stdout);
        if(miller_rabin_test(result, PRIMALITY_TEST_REPEAT))
            break;
        bignum_iadd_2(result);
    }
    printf("\n");
}

void rsa_generate_key_pair(char *ns, char *ds, char *es, char *phis, int bytes)
{
    bignum *p, *q;
    bignum *n, *d, *e, *phi;
    bignum *one;
    char *buf;

    p = bignum_alloc();
    q = bignum_alloc();
    one = bignum_alloc();
    n = bignum_alloc();
    d = bignum_alloc();
    e = bignum_alloc();
    phi = bignum_alloc();

    bignum_fromint(one, 1);
    random_prime(bytes, p);
    print_bignum("p", p);
    random_prime(bytes, q);
    print_bignum("q", q);

    bignum_multiply(n, p, q);
    bignum_isubtract(p, one);
    bignum_isubtract(q, one);
    bignum_multiply(phi, p, q);

    random_exponent(phi, EXPONENT_MAX, e);
    modular_inverse(e, phi, d);

    buf = bignum_tostring(n);
    strcpy(ns, buf); free(buf);
    buf = bignum_tostring(d);
    strcpy(ds, buf); free(buf);
    buf = bignum_tostring(e);
    strcpy(es, buf); free(buf);
    if(phis != NULL)
    {
        buf = bignum_tostring(phi);
        strcpy(phis, buf); free(buf);
    }
    bignum_free(p); bignum_free(n); bignum_free(d);
    bignum_free(q); bignum_free(e); bignum_free(phi);
    bignum_free(one);
}

void rsa_encrypt(char *result, char *plaintext, int bytes, char *modulus, char *exponent)
{
    bignum *n, *e, *ct, *pt;
    char *s;

    n = bignum_alloc();
    e = bignum_alloc();
    ct = bignum_alloc();
    pt = bignum_alloc();

    //load n,e from string
    bignum_fromstring(n, modulus);
    bignum_fromstring(e, exponent);
    bignum_fromstring(pt, plaintext);

    bignum_pow_mod(ct, pt, e, n);
    s = bignum_tostring(ct);
    strcpy(result, s);
    free(s);

    //clean up
    bignum_free(ct);
    bignum_free(pt);
    bignum_free(e);
    bignum_free(n);
}

void rsa_decrypt(char *result, char *ciphertext, int bytes, char *n, char *exponent)
{
    rsa_encrypt(result, ciphertext, bytes, n, exponent);
}

char * rsa_bin2dec(uint8_t *bin, int bytes)
{
    int i;
    bignum *base256;
    bignum *tmp, *pt;
    bignum *num256;
    char *s;

    tmp = bignum_alloc();
    base256 = bignum_alloc();
    num256 = bignum_alloc();
    pt = bignum_alloc();

    bignum_fromint(base256, 1);
    bignum_fromint(num256, 256);

    for(i = 0; i < bytes; i++)
    {
        bignum_fromint(tmp, bin[i]);
        bignum_imultiply(tmp, base256);
        bignum_iadd(pt, tmp);
        bignum_imultiply(base256, num256);
    }

    s = bignum_tostring(pt);
    bignum_free(tmp); bignum_free(base256);
    bignum_free(num256); bignum_free(pt);

    return s;
}

/*
void test1()
{
    bignum *s;
    s = bignum_alloc();
    random_prime(32, s);
    printf("%s\n", bignum_tostring(s));
    printf("%d\n", miller_rabin_test(s, 30));
    bignum_free(s);
}
*/

/*
int main()
{
    bignum *a = bignum_alloc();
    bignum *q = bignum_alloc();
    bignum *inv = bignum_alloc();
    bignum_fromstring(a, "5370702670177023357401198310401014925440001998254581061067882702546083975820467325803176536972583529046575157542254922963861667552601010631836478246909136859790891031240313975899931659373997627468479745588743233740231321214180408099897847114606064671860223946420243996731490198422261789694999790565839515281024770870764105086818848319762638885566100900975823570599688742835848176989452563188758222004735494633988600280094096160414100491691513358805586795182152183430254174163313220405487051847310519011871605356430320158997573187097059463514867880382134916538530386331818970560882451465000858533260840120529939745216");
    bignum_fromint(q, 1331748509);
    modular_inverse(q, a, inv);
    print_bignum("inv", inv);
    return 0;
}
*/
