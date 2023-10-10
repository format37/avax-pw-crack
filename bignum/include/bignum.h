#include "bn.h"

#define BN_MASK2 0xffffffff;

typedef struct bignum_st {
  BN_ULONG *d;
  int top;
  int dmax;
  int neg;
  int flags;
} BIGNUM;

__device__ void bn_print(char* msg, BIGNUM* a) {
  printf("%s", msg);
  for(int i=0; i<a->top; i++) {
    printf("%02x", a->d[i]);
    //printf("%s", BN_bn2hex(a));
  }
  printf("\n");
}

__device__ void init_zero(BIGNUM* r, int len) {
  for (int i = 0; i < len; i++) {
    r->d[i] = 0;
  }
  r->top = len;
  r->neg = 0;
}

__device__ void bn_add(BIGNUM* a, BIGNUM* b, BIGNUM* r) {
    int max = a->top > b->top ? a->top : b->top;
    BN_ULONG carry = 0;
    //printf("Starting addition... max: %d\n", max);

    for(int i=max-1; i>=0; i--) {
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        BN_ULONG sum = ai + bi + carry;
        r->d[i] = sum;
        carry = (a->d[i] + bi + carry) > 0xFFFFFFFF ? 1 : 0;


        // Debug prints
        /*printf("i: %d", i);
        printf(", a->d[i]: %08x", ai);    
        printf(", b->d[i]: %08x", bi);
        printf(", sum: %08x", sum);
        printf(", result: %08x", r->d[i]);
        printf(", carry: %08x\n", carry);*/
    }

    // If there's a carry after processing all words
    if (carry) {
        r->top = max + 1;
        for (int i = r->top-1; i > 0; i--) {
            r->d[i] = r->d[i-1];
        }
        r->d[0] = carry;
    } else {
        r->top = max;
    }

    //printf("Finished addition.\n");
    // print r
    /*printf("r: ");
    for (int i = 0; i < r->top; i++) {
        printf("%08x\n", r->d[i]);
    }*/
}

__device__ void bn_sub(BIGNUM* a, BIGNUM* b, BIGNUM* r) {
  int len = max(a->top, b->top);
  BN_ULONG borrow = 0;
  for (int i = 0; i < len; i++) {
    BN_ULONG ai = i < a->top ? a->d[i] : 0;
    BN_ULONG bi = i < b->top ? b->d[i] : 0;
    // BN_ULONG ri = ai - bi - borrow;
    /*if (ri > ai) borrow = 1;
    else borrow = 0;
    r->d[i] = ri;*/
    BN_ULONG temp = (BN_ULONG)ai - bi - borrow;
    if (temp > ai) borrow = 1;
    else borrow = 0;
    r->d[i] = (BN_ULONG) temp;
  }
  // Handle final borrow if needed
}

/*__device__ int bn_compare(const BIGNUM* a, const BIGNUM* b) {
    // Compare based on the number of valid BN_ULONG values
    if (a->top > b->top) return 1;
    if (a->top < b->top) return -1;

    // If 'top' values are equal, compare the BN_ULONG values
    for (int i = a->top - 1; i >= 0; i--) {
        if (a->d[i] > b->d[i]) return 1;
        if (a->d[i] < b->d[i]) return -1;
    }

    // If we reach here, the numbers are equal
    return 0;
}*/

/*__device__ void bn_mod_curveOrder_v0(uint32_t result[8], const uint32_t num[16]) {
    uint32_t curveOrder[8] = {0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364141};

    // Copy the input number to the result
    for (int i = 0; i < 8; i++) {
        result[i] = num[i];
    }

    // Simplified modulus operation (can be optimized further)
    while (bn_compare(result, curveOrder) >= 0) {
        bn_sub(result, result, curveOrder);
    }
}*/

__device__ void bn_init(BIGNUM *a) {
    for (int i = 0; i < 8; i++) {
        a->d[i] = 0;
    }
    a->top = 0;
}

__device__ int bn_compare(const BIGNUM *a, const BIGNUM *b) {
    for (int i = 7; i >= 0; i--) {
        if (a->d[i] > b->d[i]) return 1;
        if (a->d[i] < b->d[i]) return -1;
    }
    return 0;
}

__device__ int bn_cmp(const BIGNUM *a, const BIGNUM *b) {

  int i;

  // Compare top 
  if (a->top > b->top) return 1;
  if (a->top < b->top) return -1;

  // Compare words
  for (i = a->top - 1; i >= 0; i--) {
    if (a->d[i] > b->d[i]) return 1;
    if (a->d[i] < b->d[i]) return -1; 
  }

  // If all words equal, BIGNUMs are equal
  return 0; 

}

__device__ void bn_nnmod(BIGNUM *r, BIGNUM *m) {
// Make parameter const
  while (bn_cmp(r, m) >= 0) {
    bn_sub(r, r, m); 
  }
}

/*__device__ void bn_mod_curveOrder(BIGNUM *result, const BIGNUM *num, BIGNUM *curveOrder) {
    // print the curveOrder value
    printf("bn_mod_curveOrder: ");
    for (int i = 0; i < 8; i++) {
        printf("%08x", curveOrder->d[i]);
    }
    printf("\n");
    printf("bn_mod_curveOrder 0\n");    
    BIGNUM temp;
    // bn_init(&temp);
    printf("bn_mod_curveOrder 1\n");
    // bn_init(result);
    
    // Copy the input number to the result
    for (int i = 0; i < 8; i++) {
        result->d[i] = num->d[i];
    }
    result->top = 8;

    // Simplified modulus operation (can be optimized further)
    while (bn_compare(result, curveOrder) >= 0) {
        bn_sub(result, curveOrder, &temp);
        for (int j = 0; j < 8; j++) {
            result->d[j] = temp.d[j];
        }
    }
}*/

// old version ++
__device__ BN_ULONG bn_mod(BN_ULONG num, BN_ULONG divisor) {
  return num % divisor; 
}

__device__ BN_ULONG bn_mod_big(BIGNUM *num, BIGNUM *divisor) {

  BN_ULONG d = divisor->d[divisor->top-1]; // divisor
  BN_ULONG n = num->d[num->top-1]; // numerator
  
  return bn_mod(n, d);
}

__device__ BN_ULONG bn_mod_big_signed(BIGNUM *num, BIGNUM *divisor) {

  int numNeg = num->neg;
  int divNeg = divisor->neg;

  BN_ULONG d = divisor->d[divisor->top-1]; 
  BN_ULONG n = num->d[num->top-1];

  //BN_ULONG res = bn_mod(n, d);
  //BN_ULONG res = n % d;
  //BN_ULONG res = n & BN_MASK2;
  //BN_ULONG res = n & 0xffffffff;
  BN_ULONG res = bn_mod_big(num, divisor);

  if (numNeg) {
    res = d - res; // subtract from divisor
  }

  if (divNeg) {
    res = -res; // negate result if divisor is negative
  }

  return res;

}
// Old version --