#ifndef __BIGNUM_H__
#define __BIGNUM_H__

#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

typedef struct
{
	int length;
	int capacity;
	uint32_t * data;   //data[0] is LSB, memory allocated at runtime
} bignum;

bignum * bignum_alloc();
void bignum_free(bignum *b);

void bignum_set_zero(bignum *b);
void bignum_fromint(bignum* b, uint32_t num);
void bignum_fromstring(bignum* b, char* string);
char * bignum_tostring(bignum* b);
void bignum_copy(bignum* source, bignum* dest);

void bignum_random(int bytes, bignum *result);

//compare & testing
int bignum_iszero(bignum* b);
int bignum_isodd(bignum *b);
int bignum_isequal(bignum* b1, bignum* b2);
int bignum_isgreater(bignum* b1, bignum* b2);
int bignum_isless(bignum* b1, bignum* b2);
int bignum_isgeq(bignum* b1, bignum* b2);
int bignum_isleq(bignum* b1, bignum* b2);

//math operations
void bignum_iadd(bignum* source, bignum* add);
void bignum_iadd_2(bignum* source);
void bignum_add(bignum* result, bignum* b1, bignum* b2);
void bignum_isubtract(bignum* source, bignum* add);
void bignum_subtract(bignum* result, bignum* b1, bignum* b2);
void bignum_imultiply(bignum* source, bignum* add);
void bignum_multiply(bignum* result, bignum* b1, bignum* b2);
void bignum_idivide(bignum* source, bignum* div);
void bignum_idivide_2(bignum *source);
// void bignum_idivider(bignum* source, bignum* div, bignum* remainder);
void bignum_mod(bignum* source, bignum *div, bignum* remainder);
void bignum_imod(bignum* source, bignum* modulus);
void bignum_divide(bignum* quotient, bignum* remainder, bignum* b1, bignum* b2);

#endif
