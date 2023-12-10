#include "bn.h"

#define BN_MASK2 0xffffffff;

typedef struct bignum_st {
  BN_ULONG *d;
  int top;
  int dmax;
  int neg;
  int flags;
} BIGNUM;

__device__ void debug_printf(const char *fmt, ...) {
    if (debug_print) {
        printf(fmt);
    }
}

__device__ void bn_print(char* msg, BIGNUM* a) {
  printf("%s", msg);
  int if_zero = true;
  for(int i=0; i<a->top; i++) {
    printf("%08x", a->d[i]);
    if (a->d[i] != 0) if_zero = false;
  }
  if (if_zero) printf("0");
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

#define BN_ULONG_NUM_BITS 32 
#define MAX_BIGNUM_WORDS 8     // For 256-bit numbers
#define MAX_BIGNUM_SIZE 16     // Allow room for temp calculations

/*__device__ void bn_init_zero(BIGNUM *bn, int top) {
    // Note: This assumes that memory for bn->d has already been allocated
    // with the appropriate size beforehand.
    for (int i = 0; i < top; i++) {
        bn->d[i] = 0; // Set all digits to 0
    }
    bn->top = top; // Set the number of active words
    bn->neg = 0;   // Set the number as positive
}*/

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

/*__device__ void init_zero_v0(BIGNUM* r, int len) {
  for (int i = 0; i < len; i++) {
    r->d[i] = 0;
  }
  r->top = len;
  r->neg = 0;
}*/

__device__ void init_zero(BIGNUM *bn, int top) {
    // Assuming bn->d is already allocated and sized correctly
    if (top == MAX_BIGNUM_WORDS) {
      BN_ULONG d[MAX_BIGNUM_WORDS];
      bn->d = d;
      printf("===== < init_zero: top: %d\n", top);
      for (int i = 0; i < top; i++) {
          printf("===== < init_zero: i: %d\n", i);
          bn->d[i] = 0;
      }
      
      bn->top = (top > 0) ? 1 : 0; // If top is positive, there's at least one 0-word; otherwise, no words
      bn->neg = 0;
    }
    else {
      BN_ULONG d[MAX_BIGNUM_SIZE];    
      bn->d = d;
      printf("===== < init_zero: top: %d\n", top);
      for (int i = 0; i < top; i++) {
          printf("===== < init_zero: i: %d\n", i);
          bn->d[i] = 0;
      }
      
      bn->top = (top > 0) ? 1 : 0; // If top is positive, there's at least one 0-word; otherwise, no words
      bn->neg = 0;
    }
    
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

__device__ void bn_add(BIGNUM* a, BIGNUM* b, BIGNUM* r) {
    int max = a->top > b->top ? a->top : b->top;
    BN_ULONG carry = 0;
    //debug_printf("Starting addition... max: %d\n", max);
    /*debug_printf("Starting addition... [0_0]\n");
    // print a
    debug_printf("a: ");
    for (int i = 0; i < a->top; i++) {
        debug_printf("%08x\n", a->d[i]);
    }
    // print b
    debug_printf("b: ");
    for (int i = 0; i < b->top; i++) {
        debug_printf("%08x\n", b->d[i]);
    }
    // print r
    debug_printf("r: ");
    for (int i = 0; i < r->top; i++) {
        debug_printf("%08x\n", r->d[i]);
    }*/

    for(int i=max-1; i>=0; i--) {
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        BN_ULONG sum = ai + bi + carry;
        debug_printf("rdsum\n");
        r->d[i] = sum;
        //carry = (sum < ai || sum < bi) ? 1 : 0;  // Another way to determine carry
        debug_printf("carry");
        carry = (sum < ai || (sum - ai) < bi) ? 1 : 0;


        // Debug prints
        debug_printf("i: %d", i);
        debug_printf(", a->d[i]: %08x", ai);    
        debug_printf(", b->d[i]: %08x", bi);
        debug_printf(", sum: %08x", sum);
        debug_printf(", result: %08x", r->d[i]);
        debug_printf(", carry: %08x\n", carry);
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

    debug_printf("Finished addition.\n");
    // print r
    debug_printf("r: ");
    for (int i = 0; i < r->top; i++) {
        debug_printf("%08x\n", r->d[i]);
    }
}

__device__ void bn_add_v1(BIGNUM* a, BIGNUM* b, BIGNUM* r) {
    int max = (a->top > b->top ? a->top : b->top) + 1; // Allocate one more for potential carry

    // Expects r->d was already preallocated with a size of at least max
    // Either allocate more memory or initialize r->d before calling bn_add, like:
    // r->d = (BN_ULONG*)malloc(sizeof(BN_ULONG) * r->top);

    BN_ULONG carry = 0;
    for(int i = 0; i < max - 1; i++) { // Loop through both numbers
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0; // Safely get from a or zero
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0; // Safely get from b or zero

        unsigned long long sum = (unsigned long long)ai + bi + carry; // Avoid overflow using larger type
        r->d[i] = (BN_ULONG)(sum & 0xFFFFFFFF); // Store lower 32 bits
        carry = (BN_ULONG)(sum >> 32); // Upper 32 bits become carry
    }
    r->d[max - 1] = carry; // Store final carry, if any
    // Update the top to reflect the actual number of significant words
    r->top = (carry != 0) ? max : max - 1; // If the carry is not 0, include it in the length of r
}

 
/*__device__ BN_ULONG bn_mod(BN_ULONG num, BN_ULONG divisor) {
  return num % divisor; 
}*/

__device__ void bn_mod(BIGNUM* r, BIGNUM* m, BIGNUM* d) {
    //debug_printf("bn_mod 0\n");
    printf("bn_mod 0\n");
    // Copy m to r
    for (int i = 0; i < m->top; i++) {
        debug_printf("bn_mod: 0.%d r_top: %d m_top: %d\n", i, r->top, m->top);
        r->d[i] = m->d[i];
    }
    printf("bn_mod 1\n");
    r->top = m->top;
    r->neg = 0;
    printf("bn_mod 2\n");

    // Ensure r has enough space to cover subtraction up to d->top
    for (int i = m->top; i < d->top; i++) {
        r->d[i] = 0; // Zero out any remaining indices
    }
    printf("bn_mod 3\n");
    if (d->top > r->top) {
        r->top = d->top; // Increase the top to match d, if necessary
    }
    printf("bn_mod 4\n");

    // Keep subtracting d from r until r < d
    while (true) {
        // Check if r < d or r == d
        int compare = bn_cmp(r, d); // Need to implement bn_cmp to compare BIGNUMs
        //printf("bn_mod >> x\n");
        //printf("bn_mod >> compare: %d\n", compare);
        if (compare < 0) {
            // r < d, we are done
            //printf("bn_mod >> y\n");
            break;
        } else if (compare == 0) {
            // r == d, set r to 0 and we are done
            /*printf("bn_mod >> z\n");
            printf("bn_mod >> r_top: %d\n", r->top);
            printf("bn_mod >> r_neg: %d\n", r->neg);
            printf("bn_mod >> r_dmax: %d\n", r->dmax);
            printf("bn_mod >> r_flags: %d\n", r->flags);*/
            init_zero(r, MAX_BIGNUM_SIZE);
            // init_zero(r, MAX_BIGNUM_WORDS);
            //printf("bn_mod >> 0\n");
            break;
        }

        // r > d, so subtract d from r
        int borrow = 0;
        for (int i = 0; i < r->top; i++) {
            printf(">> bn_mod: 1.%d r_top: %d d_top: %d\n", i, r->top, d->top);
            long long res = (long long)r->d[i] - (long long)((i < d->top) ? d->d[i] : 0) - borrow;
            borrow = (res < 0) ? 1 : 0;
            if (res < 0) {
                res += (1LL << 32); // Assuming each BN_ULONG is 32 bits
            }
            r->d[i] = (BN_ULONG)res;
        }

        // Additional condition to ensure r->top shrinks if top words are zero.
        while (r->top > 0 && r->d[r->top - 1] == 0) {
            --r->top;
        }
    }
    printf("bn_mod end\n");
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