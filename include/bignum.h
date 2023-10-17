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
  }
  printf("\n");
}

__device__ BN_ULONG bn_sub_words(BN_ULONG* r, BN_ULONG* a, BN_ULONG* b, int n) {
  
  BN_ULONG borrow = 0;
  for (int i = 0; i < n; i++) {
    BN_ULONG t1 = a[i];
    BN_ULONG t2 = b[i];
    BN_ULONG w = (t1 - borrow) - t2;
    borrow = (w > t1); // handle borrow
    r[i] = w; 
  }

  return borrow;
}

__device__ void reverse(BN_ULONG* d, int n) {
  BN_ULONG tmp;
  for(int i=0; i < n/2; i++) {
    tmp = d[i];
    d[i] = d[n - i - 1];
    d[n - i - 1] = tmp; 
  }
}

__device__ void bn_sub_v0(BIGNUM* a, BIGNUM* b, BIGNUM* r) {

  // Reverse word order
  reverse(a->d, a->top); 
  reverse(b->d, b->top);

  int max = a->top; 
  int min = b->top;
  int dif = max - min;

  if (dif < 0) {
    // a must be larger than b, return error
    return;
  }

  //BN_ULONG borrow = 0;
  BN_ULONG* ap = a->d;
  BN_ULONG* bp = b->d;
  BN_ULONG* rp = r->d;

  // Subtract words 
  // borrow = bn_sub_words(rp, ap, bp, min);
  BN_ULONG borrow = bn_sub_words(rp, ap, bp, min);

  // Subtract remaining words in 'a'
  ap += min;
  rp += min;

  BN_ULONG prev = 0; // Track previous word

  while (dif) {

    // Compute subtraction for this word
    BN_ULONG cur = *(ap++);
    BN_ULONG tmp = (cur - borrow) & BN_MASK2;

    // Store result 
    *(rp++) = tmp;

    // Update borrow
    borrow = (prev == 0) & borrow; // propagate borrow

    prev = cur; // save previous word
    dif--;

  }

  // Clear leading zeros
  while (max && *(--rp) == 0) {
    max--;
  }

  // Set result  
  r->top = max;
  r->neg = 0; 

  // Reverse result for little endian
  reverse(r->d, r->top);

}

__device__ void bn_sub_v1(BIGNUM* a, BIGNUM* b, BIGNUM* r) {

  int len = max(a->top, b->top) * sizeof(BN_ULONG);
  
  unsigned char borrow = 0;

  for (int i = len-1; i >= 0; i--) {

    unsigned char ai = (a->d[i/sizeof(BN_ULONG)] >> (8*(i%sizeof(BN_ULONG)))) & 0xFF;  
    unsigned char bi = (b->d[i/sizeof(BN_ULONG)] >> (8*(i%sizeof(BN_ULONG)))) & 0xFF;

    unsigned char ri = ai - bi - borrow;

    if (ri > ai) borrow = 1;
    else borrow = 0;

    r->d[i/sizeof(BN_ULONG)] |= ri << (8*(i%sizeof(BN_ULONG)));

  }

  // Handle final borrow
  if (borrow) {
    // Underflow, error
  } else {
    // Success, set result length
  }

}

__device__ void init_zero(BIGNUM* r, int len) {
  for (int i = 0; i < len; i++) {
    r->d[i] = 0;
  }
  r->top = len;
  r->neg = 0;
}

__device__ void bn_sub(BIGNUM* a, BIGNUM* b, BIGNUM* r) {
  int len = max(a->top, b->top);
  BN_ULONG borrow = 0;
  for (int i = 0; i < len; i++) {
    BN_ULONG ai = i < a->top ? a->d[i] : 0;
    BN_ULONG bi = i < b->top ? b->d[i] : 0;
    BN_ULONG ri = ai - bi - borrow;
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

__device__ int bn_cmp(BIGNUM* a, BIGNUM* b) {
  if (a->top > b->top) return 1;
  if (a->top < b->top) return -1;
  for (int i = a->top - 1; i >= 0; i--) {
    if (a->d[i] > b->d[i]) return 1;
    if (a->d[i] < b->d[i]) return -1;
  }
  return 0;
}

__device__ void bn_add_v0(BIGNUM* a, BIGNUM* b, BIGNUM* r) {

  int max = a->top > b->top ? a->top : b->top;

  BN_ULONG carry = 0;

  printf("Starting addition...\n");

  for(int i=0; i<max; i++) {
    BN_ULONG sum = a->d[i] + b->d[i] + carry;
    r->d[i] = sum;
    carry = sum >> 32; // handle carry 
    //carry = sum >> (8 * sizeof(BN_ULONG)); // TODO: this may be wrong
    //carry = (sum & 0xFFFFFFFF00000000) >> 32;
  }

  if (carry) {
    // overflow, increase result size
    r->top = max + 1; 
    r->d[max] = carry;
  } else {
    // no overflow, set result top
    r->top = max;
  }

  // handle negative numbers
  /*if (a->neg && !b->neg) {
    // a is negative, subtract
    bn_sub(b, a, r); 
    r->neg = 1;
  } else if (!a->neg && b->neg) {
    // b is negative, subtract
    bn_sub(a, b, r);
    r->neg = 1;    
  } else {
    r->neg = 0;
  }*/
  if (a->neg && !b->neg) {
    if (bn_cmp(a, b) > 0) {
      bn_sub(a, b, r);
      r->neg = 1;
    } else {
      bn_sub(b, a, r);
    }
  } else if (!a->neg && b->neg) {
    if (bn_cmp(a, b) > 0) {
      bn_sub(a, b, r);
    } else {
      bn_sub(b, a, r);
      r->neg = 1;
    }
  }

}

__device__ void bn_add_v1(BIGNUM* a, BIGNUM* b, BIGNUM* r) {
  int max = a->top > b->top ? a->top : b->top; //k
  BN_ULONG carry = 0; //k

  printf("Starting addition... max: %d\n", max);

  for(int i=0; i<max; i++) {
    BN_ULONG ai = i < a->top ? a->d[i] : 0;
    BN_ULONG bi = i < b->top ? b->d[i] : 0;

    BN_ULONG sum = ai + bi + carry;
    r->d[i] = sum;  // Assuming BN_ULONG is 32 bits, this will only keep the lower 32 bits
    carry = sum >> (8 * sizeof(BN_ULONG));

    // Debug prints
    printf("i: %d, ai: %08x, bi: %08x, sum: %08x, result: %08x, carry: %08x\n", 
           i, ai, bi, sum, r->d[i], carry);
    // print a->d[i] and b->d[i] in hex
    printf("a->d[i]: %08x, b->d[i]: %08x\n", a->d[i], b->d[i]);
  }

  if (carry) {
    r->top = max + 1; 
    r->d[max] = carry;
    printf("Final carry: %08x\n", carry);
  } else {
    r->top = max;
  }

  printf("Finished addition.\n");
}

__device__ void bn_add_v2(BIGNUM* a, BIGNUM* b, BIGNUM* r) {
  int max = a->top > b->top ? a->top : b->top; //k
  BN_ULONG carry = 0; //k
  printf("Starting addition... max: %d\n", max);

  for(int i=0; i<max; i++) {
    
    // BN_ULONG ai = i < a->top ? a->d[i] : 0;
    BN_ULONG bi = i < b->top ? b->d[i] : 0;

    BN_ULONG sum = a->d[i] + bi + carry;
    r->d[i] = sum;  // Assuming BN_ULONG is 32 bits, this will only keep the lower 32 bits
    //carry = sum >> (8 * sizeof(BN_ULONG));
    carry = (sum >> 32) & 0x1;

    // Debug prints
    printf("i: %d", i);
    printf(", a->d[i]: %08x", a->d[i]);    
    printf(", b->d[i]: %08x", b->d[i]);
    printf(", sum: %08x", sum);
    printf(", result: %08x", r->d[i]);
    printf(", carry: %08x\n", carry);
  }

  if (carry) {
    r->top = max + 1; 
    r->d[max] = carry;
    printf("Final carry: %08x\n", carry);
  } else {
    r->top = max;
  }

  printf("Finished addition.\n");
  // print r
  printf("r: ");
  for (int i = 0; i < r->top; i++) {
    printf("%08x\n", r->d[i]);
  }
}

__device__ void bn_add(BIGNUM* a, BIGNUM* b, BIGNUM* r) {
    int max = a->top > b->top ? a->top : b->top;
    BN_ULONG carry = 0;
    printf("Starting addition... max: %d\n", max);

    for(int i=max-1; i>=0; i--) {
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        BN_ULONG sum = ai + bi + carry;
        r->d[i] = sum;
        //carry = (sum < ai || sum < bi) ? 1 : 0;  // Another way to determine carry
        carry = (sum < ai || (sum - ai) < bi) ? 1 : 0;


        // Debug prints
        printf("i: %d", i);
        printf(", a->d[i]: %08x", ai);    
        printf(", b->d[i]: %08x", bi);
        printf(", sum: %08x", sum);
        printf(", result: %08x", r->d[i]);
        printf(", carry: %08x\n", carry);
    }

    // If there's a carry after processing all words
    if (carry) {
        r->top = max + 1;
        for (int i = r->top-1; i > 0; i--) {   // Shift every word to the right
            r->d[i] = r->d[i-1];
        }
        r->d[0] = carry;  // Place the carry on the leftmost side
    } else {
        r->top = max;
    }

    printf("Finished addition.\n");
    // print r
    printf("r: ");
    for (int i = 0; i < r->top; i++) {
        printf("%08x\n", r->d[i]);
    }
}


/*__device__ BN_ULONG bn_mod(BN_ULONG num, BN_ULONG divisor) {
  return num % divisor; 
}*/

__device__ void bn_mod(BIGNUM* r, BIGNUM* m, BIGNUM* d) {
    // Copy m to r
    for (int i = 0; i < m->top; i++) {
        r->d[i] = m->d[i];
    }
    r->top = m->top;
    r->neg = 0;

    // Keep subtracting d from r until r < d
    while (true) {
        int borrow = 0;
        int is_smaller = 0;

        // Subtract d from r, with borrow
        for (int i = d->top - 1; i >= 0; i--) {
            long long res = (long long)r->d[i] - d->d[i] - borrow;
            if (res < 0) {
                res += 0x100000000;
                borrow = 1;
            } else {
                borrow = 0;
            }
            r->d[i] = (BN_ULONG)res;

            if (r->d[i] < d->d[i]) {
                is_smaller = 1;
            }
        }

        // If we had a borrow at the end, add back d to correct
        if (borrow) {
            int carry = 0;
            for (int i = d->top - 1; i >= 0; i--) {
                long long res = (long long)r->d[i] + d->d[i] + carry;
                if (res >= 0x100000000) {
                    res -= 0x100000000;
                    carry = 1;
                } else {
                    carry = 0;
                }
                r->d[i] = (BN_ULONG)res;
            }
            break;
        }

        if (is_smaller) {
            break;
        }
    }
}

/*__device__ BN_ULONG bn_mod_big(BIGNUM *num, BIGNUM *divisor) {

  BN_ULONG d = divisor->d[divisor->top-1]; // divisor
  BN_ULONG n = num->d[num->top-1]; // numerator
  
  return bn_mod(n, d);
}

__device__ BN_ULONG bn_mod_big_signed(BIGNUM *num, BIGNUM *divisor) {

  int numNeg = num->neg;
  int divNeg = divisor->neg;

  BN_ULONG d = divisor->d[divisor->top-1]; 
  BN_ULONG n = num->d[num->top-1];

  BN_ULONG res = bn_mod(n, d);

  if (numNeg) {
    res = d - res; // subtract from divisor
  }

  if (divNeg) {
    res = -res; // negate result if divisor is negative
  }

  return res;

}*/