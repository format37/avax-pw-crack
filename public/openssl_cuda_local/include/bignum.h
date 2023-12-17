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
      // printf("===== < init_zero: top: %d\n", top);
      for (int i = 0; i < top; i++) {
          // printf("===== < init_zero: i: %d\n", i);
          bn->d[i] = 0;
      }
      
      bn->top = (top > 0) ? 1 : 0; // If top is positive, there's at least one 0-word; otherwise, no words
      bn->neg = 0;
    }
    else {
      BN_ULONG d[MAX_BIGNUM_SIZE];    
      bn->d = d;
      //printf("===== < init_zero: top: %d\n", top);
      for (int i = 0; i < top; i++) {
          //printf("===== < init_zero: i: %d\n", i);
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

// Helper function to perform a deep copy of BIGNUM
/*__device__ void bn_copy(BIGNUM *dest, BIGNUM *src) {
    // printf("bn_copy");
    if (dest == nullptr || src == nullptr) return;

    // Copy the neg and top fields
    dest->neg = src->neg;
    dest->top = src->top;

    // Copy the array of BN_ULONG digits.
    // MAX_BIGNUM_WORDS would be the maximum number of words in the BIGNUM variable
    for (int i = 0; i < src->top; i++) {
        dest->d[i] = src->d[i];
    }

    // Set the rest of the words in dest to 0 if dest's top is larger
    for (int i = src->top; i < dest->top; i++) {
        dest->d[i] = 0;
    }
}*/

__device__ int simple_BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d)
{
    // Check for division by zero
    if (d->top == 0) {
        return 0; // Error code
    }

    // Perform the modulo operation; this is a simplified operation assuming single-precision
    BN_ULONG remainder = m->d[0] % d->d[0];

    // Check the sign and adjust if necessary
    if (m->neg) {
        remainder = d->d[0] - remainder;
    }

    // Update the result BIGNUM
    r->d[0] = remainder;
    r->top = 1; // Simplified; assuming single-precision arithmetic
    r->neg = 0; // Result is always non-negative

    return 1; // Success
}

__device__ void big_num_add_mod(BN_ULONG *result, BN_ULONG *a, BN_ULONG *b, BN_ULONG *n, int num_words) {
    BN_ULONG carry = 0;
    for (int i = num_words - 1; i >= 0; i--) {
        unsigned long long sum = (unsigned long long) a[i] + (unsigned long long) b[i] + carry; // Use 64-bit to prevent overflow
        result[i] = (BN_ULONG) (sum % 0x100000000);  // Keep lower 32 bits
        carry = (BN_ULONG) (sum >> 32); // Upper 32 bits become carry
    }

    // Modular reduction: simply subtract n from result if result >= n
    for (int i = 0; i < num_words; i++) {
        if (result[i] < n[i]) return; // Early exit if we find a smaller component
        if (result[i] > n[i]) break; // Continue if we find a larger component
    }
    // At this point, we know result >= n, so perform result -= n
    carry = 0;
    for (int i = num_words - 1; i >= 0; i--) {
        long long diff = (long long) result[i] - (long long) n[i] - carry; // Use 64-bit to prevent underflow
        if (diff < 0) {
            diff += 0x100000000; // Borrow from next word
            carry = 1;
        } else {
            carry = 0;
        }
        result[i] = (BN_ULONG) diff;
    }
}

__device__ void robust_BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d) {
    // Copy m into r
    for (int i = 0; i < m->top; ++i) {
        r->d[i] = m->d[i];
    }
    r->top = m->top;
    r->neg = 0;  // Result is non-negative

    // Now we'll reduce r modulo d, using simple division
    for (int i = 0; i < r->top; ++i) {
        if (r->d[i] >= d->d[0]) {
            BN_ULONG quotient = r->d[i] / d->d[0];
            BN_ULONG remainder = r->d[i] % d->d[0];

            // Subtract quotient*d from r
            BN_ULONG borrow = 0;
            for (int j = 0; j < d->top; ++j) {
                unsigned long long sub = (unsigned long long) r->d[i+j] - (unsigned long long) d->d[j] * quotient - borrow;
                r->d[i+j] = (BN_ULONG) (sub % 0x100000000);
                borrow = (BN_ULONG) (sub >> 32);
            }

            // Add back the remainder at position i
            unsigned long long sum = (unsigned long long) r->d[i] + (unsigned long long) remainder;
            r->d[i] = (BN_ULONG) (sum % 0x100000000);
            BN_ULONG carry = (BN_ULONG) (sum >> 32);

            // Propagate any carry
            for (int j = i+1; j < r->top && carry; ++j) {
                sum = (unsigned long long) r->d[j] + carry;
                r->d[j] = (BN_ULONG) (sum % 0x100000000);
                carry = (BN_ULONG) (sum >> 32);
            }

            // If there's still a carry, increase the size of r
            if (carry) {
                r->d[r->top] = carry;
                r->top++;
            }
        }
    }
}

// Public key derivation ++
/*#define MAX_BIGNUM_WORDS 8 // Assuming 256-bit numbers
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)
#define MAX_BIGNUM_SIZE 16 // For holding up to a 512-bit number TODO: maybe 256 ?
//#define MAX_BIGNUM_SIZE 8 // For holding up to a 512-bit number TODO: maybe 256 ?*/
__device__ BIGNUM CURVE_P;
__device__ BIGNUM CURVE_A;
__device__ BIGNUM CURVE_B;
__device__ BIGNUM CURVE_GX;
__device__ BIGNUM CURVE_GY;
__device__ BN_ULONG CURVE_P_d[8];
__device__ BN_ULONG CURVE_A_d[8];
__device__ BN_ULONG CURVE_B_d[8];
__device__ BN_ULONG CURVE_GX_d[8];
__device__ BN_ULONG CURVE_GY_d[8];

struct EC_POINT {
  BIGNUM x; 
  BIGNUM y;
};

__device__ void bn_div(BIGNUM *a, BIGNUM *b, BIGNUM *q, BIGNUM *r);
__device__ void bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *product);
__device__ void bn_sub(BIGNUM *a, BIGNUM *b, BIGNUM *r);

/*__device__ void bn_init_zero(BIGNUM *bn, int top) {
    // Note: This assumes that memory for bn->d has already been allocated
    // with the appropriate size beforehand.
    for (int i = 0; i < top; i++) {
        bn->d[i] = 0; // Set all digits to 0
    }
    bn->top = top; // Set the number of active words
    bn->neg = 0;   // Set the number as positive
}*/

__device__ void set_bn(BIGNUM *dest, const BIGNUM *src) {
    debug_printf("set_bn 0\n");

    // Check if dest has enough space to copy from src
    if (dest->dmax < src->top) {
        // Handle the situation appropriately
        // Depending on how memory is managed, this could be an error or resize operation
        return;
    }

    // Copy over the significant words from source to destination.
    for (int i = 0; i < src->top; ++i) {
        debug_printf("set_bn 1.%d\n", i);
        dest->d[i] = src->d[i];
    }

    // Zero out any remaining entries in the array if the source 'top' is less than the dest 'dmax'
    for (int i = src->top; i < dest->dmax; ++i) {
        debug_printf("set_bn 2.%d\n", i);
        dest->d[i] = 0;
    }

    debug_printf("set_bn 3\n");

    // Set the 'top' and 'neg' flags after zeroing
    dest->top = src->top;
    dest->neg = src->neg;
}

// In the current structure, we might use a specific value (e.g., 0 or -1) 
// to represent the components of the point at infinity.

// A version that uses 0 to signify the point at infinity could be:
__device__ int point_is_at_infinity(EC_POINT *P) {
    /*debug_printf("# point_is_at_infinity:\n");
    bn_print("P->x: ", &P->x);
    bn_print("P->y: ", &P->y);
    debug_printf("# P->x.top: %d\n", P->x.top);*/
    /*if (P->x.top == 0) {
        debug_printf("returning 1\n");
        return 1; // P is the point at infinity
    }
    debug_printf("returning 0\n");
    return 0; // P is not the point at infinity*/
    return P->x.top == 0; // Assuming a valid x coordinate can never have top == 0, except for the point at infinity
    /*
    // Assuming the x-coordinate is represented as an array of BN_ULONG
    // with 'top' items, and that the point at infinity has all its
    // BN_ULONGs set to 0.
    
    // If we like to detect a "point at infinity" by checking if the first word
    // is zero and making an assumption that this can only happen for the point at infinity:
    if (P->x.top == 0 && P->x.d[0] == 0) {
        return 1; // P is the point at infinity
    }

    return 0; // P is not the point at infinity
    */
}

// __device__ void mod_inv(BIGNUM *value, BIGNUM *mod, BIGNUM *inv);
// __device__ int extended_gcd(BIGNUM *a, BIGNUM *p, BIGNUM *x, BIGNUM *y);

// Assuming 'a' and 'mod' are coprime, output 'x' such that: a*x ≡ 1 (mod 'mod')
// Pseudo code for Extended Euclidean Algorithm in CUDA
__device__ int extended_gcd(BIGNUM *a, BIGNUM *mod, BIGNUM *x, BIGNUM *y) {
    // Initialization of prev_x, x, last_y, and y is omitted here but important.
    BIGNUM prev_x, last_y, last_remainder, remainder, quotient, temp;
    // Initialize prev_x = 1, x = 0, last_y = 0, y = 1 
    // Initialize last_remainder = mod, remainder = a

    // Initialize a BIGNUM for zero.
    BIGNUM zero;
    BN_ULONG zero_d[1] = {0}; // Assuming BN_ULONG is the type used to represent a single "word" of the BIGNUM.

    zero.d = zero_d;
    // zero.top = (zero_d[0] != 0); // If we've set zero_d[0] to 0, zero's top should be zero, implying an actual value of 0.
    zero.top = 0;
    zero.dmax = 1; // The maximum number of "words" in the BIGNUM. Since zero is just 0, this is 1.

    BIGNUM *temp_remainder = new BIGNUM(); // If dynamic memory is allowed - or statically allocate enough space if not

    while (bn_cmp(&remainder, &zero) != 0) {
        // bn_div(&last_remainder, &remainder, &quotient);
        bn_div(&last_remainder, &remainder, &quotient, temp_remainder); // Now using 4 arguments
        BIGNUM swap_temp = last_remainder; // Temporary storage for the swap
        last_remainder = *temp_remainder;
        *temp_remainder = swap_temp;

        bn_mul(&quotient, x, &temp); // temp = quotient*x
        bn_sub(&prev_x, &temp, &prev_x); // new prev_x = prev_x - temp
        bn_mul(&quotient, y, &temp); // temp = quotient*y
        bn_sub(&last_y, &temp, &last_y); // new last_y = last_y - temp
        
        // Swap last_remainder with remainder
        // Swap prev_x with x
        // Swap last_y with y
    }

    // Clean up
    delete temp_remainder; // Only if dynamic memory is allowed - if you statically allocated, this is unnecessary
    
    set_bn(x, &prev_x);
    set_bn(y, &last_y);

    return 1; // In this simplified version, we'd return the gcd, but we're presuming a==1
}

__device__ void mod_inv(BIGNUM *value, BIGNUM *mod, BIGNUM *inv) {
    debug_printf("mod_inv 0\n");
    BIGNUM x, y;
    // You need to make sure that BIGNUM x, y are initialized properly with minted memory
    // You also need a proper gcd implementation on GPU here.
    int g = extended_gcd(value, mod, &x, &y);
    
    // In case x is negative, we add mod to it, assuming mod>0
    if (x.neg) {
        debug_printf("mod_inv a.0\n");
        // BN_ULONG zero = 0;
        bn_add(&x, mod, inv);
        debug_printf("mod_inv a.1\n");
        bn_mod(inv, mod, inv);
        debug_printf("mod_inv a.2\n");
    } else {
        debug_printf("mod_inv b.0\n");
        bn_mod(&x, mod, inv);
        debug_printf("mod_inv b.1\n");
    }
}

__device__ void bn_sub(BIGNUM *a, BIGNUM *b, BIGNUM *r) {
    int max = a->top > b->top ? a->top : b->top;
    BN_ULONG borrow = 0;
    
    for (int i = 0; i < max; ++i) {
        debug_printf("# 4.%d\n", i);
        BN_ULONG ai = (i < a->top) ? a->d[i] : 0;
        BN_ULONG bi = (i < b->top) ? b->d[i] : 0;

        // Check if a subtraction would cause a borrow
        if (ai >= bi + borrow) {
            debug_printf("# 5\n");
            debug_printf("r->top: %d\n", r->top);
            debug_printf("i: %d\n", i);
            debug_printf("r->d[i]: %llu\n", r->d[i]);
            debug_printf("ai: %llu\n", ai);
            debug_printf("bi: %llu\n", bi);
            debug_printf("borrow: %llu\n", borrow);            
            r->d[i] = ai - bi - borrow;
            debug_printf("# 6\n");
            borrow = 0;
        } else {
            // Borrow from the next highest bit
            r->d[i] = (1ULL << (sizeof(BN_ULONG) * 8)) + ai - bi - borrow;
            borrow = 1;
        }
    }
    debug_printf("# 8\n");
    // Set result top and sign
    r->top = a->top; // r will have at most as many words as a
    for (int i = r->top - 1; i >= 0; --i) {
        if (r->d[i] != 0) {
            break;
        }
        r->top--; // Reduce top for each leading zero
    }

    // Detect underflow
    if (borrow != 0) {
        // Handle result underflow if needed (b > a)
        debug_printf("Underflow detected\n");
        // Set r to correct value or raise an error
    }
    
    r->neg = 0; // Assuming we don't want negative numbers, otherwise set sign properly
}


__device__ void bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *product) {
    // Assuming all BIGNUMs are initialized, and all the `d` arrays have enough allocated memory.
    
    // Initialize product to zero.
    for (int i = 0; i < product->dmax; i++) {
        product->d[i] = 0;
    }
    product->top = 0;

    // Multiply each digit of a by each digit of b, accumulate results in product
    for (int i = 0; i < a->top; i++) {
        BN_ULONG carry = 0;
        for (int j = 0; j < b->top || carry; j++) {
            // Perform the multiplication (and add the carry from the previous operation)
            unsigned long long sum = product->d[i + j] + carry +
                (j < b->top ? ((unsigned long long)a->d[i] * b->d[j]) : 0);

            product->d[i + j] = (BN_ULONG)(sum & 0xFFFFFFFF); // Cast here depends on the size of BN_ULONG
            
            // Compute the carry for the next round of addition
            carry = (BN_ULONG)(sum >> 32); // Assuming BN_ULONG is 32-bits
        }

        // Update the top, which tracks the number of valid words in the product
        // This assumes that bn_add updates product->top.
        if (i + b->top > product->top) {
            product->top = i + b->top;
        }
    }

    // Now product contains the product of a and b, without modulo operation.
    // If necessary, perform a modulo operation here (modular reduction), or separately after calling bn_mul.
}

__device__ void bn_add_bit(BIGNUM *a, int bit_index) {
    // Determine the word in the array where this bit resides.
    int word_index = bit_index / (sizeof(BN_ULONG) * 8);
    int bit_in_word = bit_index % (sizeof(BN_ULONG) * 8);

    // Set this bit. BN_ULONG is assumed to be large enough to handle the shifts without overflow.
    BN_ULONG bit_to_set = ((BN_ULONG)1) << bit_in_word;

    // Add the bit to the BIGNUM. This is safe from overflow because we're only setting one bit.
    a->d[word_index] |= bit_to_set;

    // Update 'top'. If we added a bit beyond the current 'top', we'll need to expand it.
    if (word_index >= a->top) {
        // Make sure we've added a bit that's not in the leading zeroes of the BIGNUM.
        // If so, `top` needs to reflect this new significant word.
        a->top = word_index + 1;

        // Ensure all bits above the current one are set to 0 in the new top 'word'.
        for (int i = bit_in_word + 1; i < sizeof(BN_ULONG) * 8; i++) {
            a->d[word_index] &= ~(((BN_ULONG)1) << i);
        }
    }
}

__device__ int bn_is_bit_set(const BIGNUM *bn, int bit_index) {
    // Check if the bit index is within the range of the BIGNUM's length
    if (bit_index < 0 || bit_index >= bn->top * BN_ULONG_NUM_BITS) {
        return 0; // Bit out of range, return 0 indicating not set
    }

    // Calculate which word and which bit within that word we are interested in
    int word_index = bit_index / BN_ULONG_NUM_BITS;
    int bit_position = bit_index % BN_ULONG_NUM_BITS;

    // Create a mask for the bit within the word
    BN_ULONG mask = (BN_ULONG)1 << bit_position;

    // Check if the bit is set and return the appropriate value
    return (bn->d[word_index] & mask) ? 1 : 0;
}

__device__ void bn_lshift(BIGNUM *a, int shift) {
    if (shift <= 0) {
        // No shift or invalid shift count; do nothing.
        return;
    }

    // Perform the shift for each word from the most significant down to the least significant.
    BN_ULONG carry = 0;
    for (int i = a->top - 1; i >= 0; --i) {
        BN_ULONG new_carry = a->d[i] >> (BN_ULONG_NUM_BITS - shift); // Capture the bits that will be shifted out.
        a->d[i] = (a->d[i] << shift) | carry; // Shift current word and add bits from previous carry.
        carry = new_carry; // Update carry for the next iteration.
    }

    // Update the 'top' if the left shift carried out of the msb.
    if (carry != 0) {
        if (a->top < a->dmax) {
            a->d[a->top] = carry; // Assign the carry to the new most significant word.
            a->top++; // Increase the top to account for the new most significant word.
        } else {
            // Handle overflow case where there's no room for an extra word.
            // This would require either halting with an error or reallocating a->d.
            debug_printf("Error: no room for extra word in bn_lshift\n");
        }
    }
}

__device__ void bn_div(BIGNUM *a, BIGNUM *b, BIGNUM *q, BIGNUM *r) {
    // Initialize quotient and remainder to zero.
    for (int i = 0; i < q->dmax; ++i) q->d[i] = 0;
    for (int i = 0; i < r->dmax; ++i) r->d[i] = 0;
    
    // Initialize remainder with dividend 'a'.
    set_bn(r, a);

    // Normalize based on the highest set bit of divisor 'b'
    int n = b->top * sizeof(BN_ULONG) * 8; // n is total number of bits in b
    
    // Find the highest set bit for normalization.
    while (n > 0 && !bn_is_bit_set(b, n - 1)) --n;
    
    // Long division algorithm.
    for (int i = a->top * sizeof(BN_ULONG) * 8 - n; i >= 0; --i) {
        // Shift q and r left by 1 bit.
        bn_lshift(q, 1);
        bn_lshift(r, 1);
        
        // If bit 'i' of a is set, add 1 to r.
        if (bn_is_bit_set(a, i)) {
            bn_add_bit(r, 0); // Assuming you have a function to add a bit at position 0.
        }
        
        // If r >= b, set bit 0 of q and subtract b from r.
        if (bn_cmp(r, b) >= 0) {
            bn_sub(r, b, r);
            bn_add_bit(q, 0); // Assuming you have a function to add a bit at position 0.
        }
    }
}

// __device__ void mod_mul(BIGNUM *a, BIGNUM *b, BIGNUM *mod, BIGNUM *result);

__device__ void mod_mul(BIGNUM *a, BIGNUM *b, BIGNUM *mod, BIGNUM *result) {
    debug_printf("mod_mul 0\n");
    // Product array to store the intermediate multiplication result
    BN_ULONG product_d[MAX_BIGNUM_SIZE] ={0}; // All elements initialized to 0
    // Ensure that 'product' uses this pre-allocated array
    BIGNUM product = { product_d, 0, MAX_BIGNUM_SIZE };
    debug_printf("mod_mul 1\n");
    // Now, you can call the bn_mul function and pass 'product' to it
    bn_mul(a, b, &product);
    debug_printf("mod_mul 2\n");
    
    
    bn_mod(&product, mod, result); // TODO: fix it


    debug_printf("mod_mul 3\n");

    // Wipe the product memory if necessary
    for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
        product_d[i] = 0;
    }
}

__device__ void point_double(EC_POINT *P, EC_POINT *R, BIGNUM *p) {
    // Temporary storage for the calculations
    BIGNUM s, xR, yR, m;
    debug_printf("point_double 0\n");
    if (point_is_at_infinity(P)) {
        debug_printf("point_double 1\n");
        // Point doubling at infinity remains at infinity
        set_bn(&R->x, &P->x);  // Copying P->x to R->x, assuming these are in the proper zeroed state
        set_bn(&R->y, &P->y);  // Copying P->y to R->y
        debug_printf("# 2\n");
        return;
    }
    debug_printf("point_double 3\n");

    // Calculate m = 3x^2 + a (a is zero for secp256k1)
    mod_mul(&P->x, &P->x, p, &m);  // m = x^2 mod p
    debug_printf("point_double 4\n");
    set_bn(&s, &m);                 // s = x^2 (Since we use a=0 in secp256k1, skip adding 'a')
    bn_add(&m, &m, &s);             // s = 2x^2
    bn_add(&s, &m, &s);             // s = 3x^2
    
    // Calculate s = (3x^2 + a) / (2y) = (s) / (2y)
    // First, compute the modular inverse of (2y)
    BIGNUM two_y;
    debug_printf("point_double 5\n");
    set_bn(&two_y, &P->y);         // Assuming set_bn simply duplicates P->y
    debug_printf("point_double 6\n");
    bn_add(&two_y, &two_y, &two_y); // two_y = 2y
    BIGNUM inv_two_y;
    debug_printf("point_double 7\n");
    mod_inv(&two_y, p, &inv_two_y);  // Compute the inverse of 2y
    debug_printf("point_double 8\n");

    mod_mul(&s, &inv_two_y, p, &s);  // Finally, s = (3x^2 + a) / (2y) mod p
    
    // Compute xR = s^2 - 2x mod p
    mod_mul(&s, &s, p, &xR);        // xR = s^2 mod p    
    set_bn(&m, &P->x);              // m = x
    
    bn_add(&m, &m, &m);             // m = 2x
    bn_sub(&xR, &m, &xR);           // xR = s^2 - 2x
    bn_mod(&xR, p, &xR);            // Modulo operation

    // Compute yR = s * (x - xR) - y mod p
    bn_sub(&P->x, &xR, &yR);        // yR = x - xR
    mod_mul(&s, &yR, p, &yR);       // yR = s * (x - xR)
    bn_sub(&yR, &P->y, &yR);        // yR = s * (x - xR) - y
    bn_mod(&yR, p, &yR);            // Modulo operation

    // Copy results to R only after all calculations are complete to allow in-place doubling (P == R)
    set_bn(&R->x, &xR);
    set_bn(&R->y, &yR);
}

/*__device__ void point_add_v0(EC_POINT *P, EC_POINT *Q, EC_POINT *R, BIGNUM *p) {
    debug_printf("# 1\n");
    // Check if one of the points is the point at infinity
    if (point_is_at_infinity(P)) {
        *R = *Q;
        return;
    }
    
    if (point_is_at_infinity(Q)) {
        *R = *P;
        return;
    }
    
    // Check if P == Q (point doubling)
    if (bn_cmp(&P->x, &Q->x) == 0 && bn_cmp(&P->y, &Q->y) == 0) {
        // call point_double
        // point_double(P, R, p);
        
        // We don't need to double the point. We can just add it to itself.
        point_add(P, P, R, p);
        return;
    }
    
    BIGNUM s, m, xR, yR;

    // Calculate slope (s = (yQ - yP) * inv(xQ - xP) mod p)
    BIGNUM tmp1, tmp2;
    debug_printf("# 2\n");
    bn_sub(&Q->y, &P->y, &tmp1); // yQ - yP
    debug_printf("# 100\n");
    bn_sub(&Q->x, &P->x, &tmp2); // xQ - xP
    mod_inv(&tmp2, p, &tmp2);     // inv(xQ - xP)
    mod_mul(&tmp1, &tmp2, p, &s); // (yQ - yP) * inv(xQ - xP)
    
    // Calculate xR (xR = s^2 - xP - xQ mod p)
    mod_mul(&s, &s, p, &xR); // s^2
    bn_sub(&xR, &P->x, &xR); // s^2 - xP
    bn_sub(&xR, &Q->x, &xR); // s^2 - xP - xQ
    bn_mod(&xR, p, &xR);     // mod p

    // Calculate yR (yR = s * (xP - xR) - yP mod p)
    bn_sub(&P->x, &xR, &yR); // xP - xR
    mod_mul(&s, &yR, p, &yR); // s * (xP - xR)
    bn_sub(&yR, &P->y, &yR);  // s * (xP - xR) - yP
    bn_mod(&yR, p, &yR);      // mod p

    // Set result
    set_bn(&R->x, &xR);
    set_bn(&R->y, &yR);
}*/

__device__ bool bn_is_zero(BIGNUM *a) {
    for (int i = 0; i < a->top; ++i) {
        if (a->d[i] != 0) {
            return false;
        }
    }
    return true;
}

__device__ bool bn_is_one(BIGNUM *a) {
    // Assuming that BIGNUM stores the number in an array 'd' of integers
    // and 'top' indicates the number of chunks being used.
    // We also assume that 'd' is big-endian and 'top' is the index of the highest non-zero digit.
    
    // The number one would be represented with only the least significant digit being one
    // and all other digits being zero.
    if (a->top != 1) {  // If there are more than one digits in use, it cannot be one
        return false;
    }
    if (a->d[0] != 1) {  // The number one should only have the least significant digit set to one
        return false;
    }
    // Ensure that any other digits (if they exist in memory) are zero
    // This isn't strictly necessary if the 'top' index is always accurate
    // but is a good sanity check if there's any possibility of memory corruption or improper initialization.
    for (int i = 1; i < MAX_BIGNUM_WORDS; ++i) {
        if (a->d[i] != 0) {
            return false;
        }
    }
    return true;
}

/*__device__ void bn_neg(BIGNUM *a, BIGNUM *result, BIGNUM *p) {
    if (bn_is_zero(a)) {
        // If a is 0, then -a (mod p) is also 0
        set_bn(result, a);
    } else {
        // Compute -a (mod p) as p - a
        bn_sub(p, a, result); // result = p - a
        bn_mod(result, p, result); // Ensure result is within [0, p-1]
    }
}*/
__device__ int bn_is_negative(const BIGNUM *a) {
    // Assuming the neg field is defined and holds the sign (0 for non-negative, 1 for negative)
    return a->neg != 0;
}

__device__ void point_add_v0(EC_POINT *P, EC_POINT *Q, EC_POINT *R, BIGNUM *p) {
    // Check if one of the points is the point at infinity
    if (point_is_at_infinity(P)) {
        *R = *Q;
        printf("point_is_at_infinity(P)\n");
        return;
    }
    
    if (point_is_at_infinity(Q)) {
        *R = *P;
        printf("point_is_at_infinity(Q)\n");
        return;
    }
    BN_ULONG tmp1_d[MAX_BIGNUM_WORDS], tmp2_d[MAX_BIGNUM_WORDS];
    BN_ULONG s_d[MAX_BIGNUM_WORDS];
    BN_ULONG xR_d[MAX_BIGNUM_WORDS], yR_d[MAX_BIGNUM_WORDS];

    // Initialize temporary BIGNUMs used for calculations
    BIGNUM tmp1, tmp2, s, xR, yR;
    tmp1.d = tmp1_d; init_zero(&tmp1, MAX_BIGNUM_WORDS);
    tmp2.d = tmp2_d; init_zero(&tmp2, MAX_BIGNUM_WORDS);
    s.d = s_d;       init_zero(&s, MAX_BIGNUM_WORDS);
    xR.d = xR_d;     init_zero(&xR, MAX_BIGNUM_WORDS);
    yR.d = yR_d;     init_zero(&yR, MAX_BIGNUM_WORDS);

    // Calculate xR = s^2 - xP - xQ
    mod_mul(&s, &s, p, &xR);   // xR = s^2
    bn_sub(&xR, &P->x, &xR);   // xR = xR - xP (s^2 - xP)
    bn_sub(&xR, &Q->x, &xR);   // xR = xR - xQ (s^2 - xP - xQ)
    bn_mod(&xR, p, &xR);       // xR = xR mod p

    // Calculate yR = s * (xP - xR) - yP
    bn_sub(&P->x, &xR, &yR);   // yR = xP - xR
    mod_mul(&s, &yR, p, &yR);  // yR = s * (xP - xR)
    bn_sub(&yR, &P->y, &yR);   // yR = yR - yP (s * (xP - xR) - yP)
    bn_mod(&yR, p, &yR);       // yR = yR mod p

    // Set result
    set_bn(&R->x, &xR);
    set_bn(&R->y, &yR);
}

// Utility function to set a BIGNUM to zero
/*__device__ void bn_zero(BIGNUM *bn) {
    if (bn != nullptr) {
        bn->neg = 0;
        bn->top = 0;

        // Assuming BIGNUM d is a pointer to an array of BN_ULONG and the array size is MAX_BIGNUM_WORDS
        for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
            bn->d[i] = 0;
        }
    }
}*/

// Helper function to perform a deep copy of BIGNUM
__device__ void bn_copy(BIGNUM *dest, BIGNUM *src) {
    // printf("bn_copy");
    if (dest == nullptr || src == nullptr) return;

    // Copy the neg and top fields
    dest->neg = src->neg;
    dest->top = src->top;

    // Copy the array of BN_ULONG digits.
    // MAX_BIGNUM_WORDS would be the maximum number of words in the BIGNUM variable
    for (int i = 0; i < src->top; i++) {
        dest->d[i] = src->d[i];
    }

    // Set the rest of the words in dest to 0 if dest's top is larger
    for (int i = src->top; i < dest->top; i++) {
        dest->d[i] = 0;
    }
}

__device__ void copy_point(EC_POINT *dest, EC_POINT *src) {
    //printf("copy_point 0\n");
    // Assuming EC_POINT contains BIGNUM structures for x and y,
    // and that BIGNUM is a structure that contains an array of BN_ULONG for the digits,
    // along with other metadata (like size, top, neg, etc.)

    // init the dest point
    dest->x.d = new BN_ULONG[MAX_BIGNUM_WORDS];
    dest->y.d = new BN_ULONG[MAX_BIGNUM_WORDS];
    dest->x.top = 0;
    dest->y.top = 0;
    dest->x.neg = 0;
    dest->y.neg = 0;
    dest->x.dmax = MAX_BIGNUM_WORDS;
    dest->y.dmax = MAX_BIGNUM_WORDS;

    // Copy the BIGNUM x
    bn_copy(&dest->x, &src->x);
    /*for (int i = 0; i < src->x.top; i++) {
        printf("copy_point 1.%d\n", i);
        dest->x.d[i] = src->x.d[i];
    }    
    dest->x.neg = src->x.neg;
    dest->x.top = src->x.top;*/

    // Copy the BIGNUM y
    bn_copy(&dest->y, &src->y);
    /*
    for (int i = 0; i < src->y.top; i++) {
        dest->y.d[i] = src->y.d[i];
    }
    dest->y.neg = src->y.neg;
    dest->y.top = src->y.top;*/
}

__device__ void set_point_at_infinity(EC_POINT *point) {
    // Assuming EC_POINT is a structure containing BIGNUM x and y
    // and that a BIGNUM value of NULL or {0} represents the point at infinity

    // To set the point at infinity, one straightforward way is to assign
    // a null pointer to x and y if the BIGNUM structure allows it, or 
    // set their values to some predetermined sentinel value that indicates
    // the point at infinity.

    // If using the sentinel value approach - ensure BIGNUM is set in a way
    // that other functions can check for it and treat it as infinity

    // To set the point to 0 (as an example sentinel value), do:
    // bn_zero(&point->x); // A function that sets a BIGNUM to 0
    init_zero(&point->x, MAX_BIGNUM_WORDS);

    //bn_zero(&point->y); // Ensure that this logic matches how you identify point at infinity elsewhere
    init_zero(&point->y, MAX_BIGNUM_WORDS);
}

__device__ void bn_subtract(BIGNUM *result, BIGNUM *a, BIGNUM *b) {
    BN_ULONG borrow = 0;
    BN_ULONG temp_borrow;

    // It's assumed that BN_ULONG is an unsigned type like uint32_t or uint64_t and that
    // a and b have the same number of words (this can be adjusted as needed)
    
    for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
        temp_borrow = (a->d[i] < b->d[i] + borrow); // Calculate if we need to borrow from the next digit
        result->d[i] = a->d[i] - b->d[i] - borrow;   // Perform the subtraction with previous borrow, if any
        borrow = temp_borrow;                        // Set borrow for the next iteration
    }

    // If there's remaining borrow at the end, the result is negative
    // which should not happen for BIGNUM in cryptographic applications, as these should
    // be operating in the context of a modulus (wrap around behavior). 
    // You'll need to assert borrow is 0 or handle it appropriately with your application's logic.

    // Update the metadata (top) if necessary
    // The 'top' can be adjusted based on the significant digits after subtraction.
    // result->top = ... (code to update the 'top' field of result, if BIGNUM has such a field)
}

__device__ void bn_set_word(BIGNUM *bn, BN_ULONG word) {
    // Assuming d is a pointer to an array where the BIGNUM's value is stored
    // and top is an integer representing the index of the most significant word + 1
    // Setting a BIGNUM to a single-word value means that all other words are zero.

    // Clear all words in the BIGNUM
    for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
        bn->d[i] = 0;
    }

    // Set the least significant word to the specified value
    bn->d[0] = word;

    // Update top to indicate that there's at least one significant digit
    bn->top = (word == 0) ? 0 : 1;

    // If using a sign flag, ensure the BIGNUM is set to non-negative
    if (bn->top) {
        bn->neg = 0;
    }
}

__device__ void bn_lshift_res(BIGNUM *result, BIGNUM *a, int shift) {
    if (shift <= 0) {
        // No shift or invalid shift count; copy input to output with no modifications.
        bn_copy(result, a);
        printf("bn_lshift_res 0\n");
        return;
    }

    // Initialize result BIGNUM according to your BIGNUM structure definition
    // Make sure that result->d has enough space to hold the result

    // Perform the shift for each word from the least significant upwards.
    BN_ULONG carry = 0;
    for (int i = 0; i < a->top; ++i) {
        printf("bn_lshift_res [%d]\n", i);
        bn_print("a: ", a);        
        BN_ULONG new_carry = a->d[i] >> (BN_ULONG_NUM_BITS - shift); // Capture the bits that will be shifted out.
        printf("new_carry: %llu\n", new_carry);
        result->d[i] = (a->d[i] << shift) | carry; // Shift current word and add bits from previous carry.
        printf("result->d[i]: %llu\n", result->d[i]);
        carry = new_carry; // Update carry for the next iteration.
    }

    // Assign the carry to the new most significant word if needed.
    if (carry != 0) {
        printf("bn_lshift_res 1\n");
        bn_print("result 0: ", result);
        result->d[a->top] = carry; // Assign the carry to the new most significant word.
        printf("result->d[a->top]: %llu\n", result->d[a->top]);
        result->top = a->top + 1;
        printf("result->top: %d\n", result->top);
    } else {
        printf("bn_lshift_res 2\n");
        bn_print("result 1: ", result);
        result->top = a->top;
        printf("result->top: %d\n", result->top);
    }

    // Initialize any remaining higher-order words to zero if necessary
    // This depends on the internals of your BIGNUM structure.
    for (int i = result->top; i < result->dmax; ++i) {
        result->d[i] = 0;
    }
    printf("bn_lshift_res 3\n");
}

#define WORD_BITS 32  // or: #define WORD_BITS (8 * sizeof(BN_ULONG))

// Helper function to get the index of the MSB within a single word
__device__ int get_msb_index(BN_ULONG word) {
    // This is a simple example using a linear scan; this can be made more efficient, for example,
    // by using the built-in __clz() or similar instructions specific to your architecture.
    for (int i = WORD_BITS - 1; i >= 0; --i) {
        if ((word >> i) & 1) {
            return i;
        }
    }
    return -1;  // if the word is zero, return -1 or another error indicator
}

__device__ int bn_get_top_bit(const BIGNUM *bn) {
    // Start scanning from the most significant word
    for (int i = bn->top - 1; i >= 0; --i) {
        int msb_index = get_msb_index(bn->d[i]);
        if (msb_index != -1) {  // If a bit is set in this word
            return i * WORD_BITS + msb_index;  // Return the global index of the MSB
        }
    }
    // If no bit is set in any word, this represents the number zero, and there is no MSB.
    return -1;  // The number is zero, so return -1 or another error indicator
}

__device__ void bn_divide(BIGNUM *quotient, BIGNUM *remainder, BIGNUM *dividend, BIGNUM *divisor) {
    // Initialize the quotient and remainder
    // bn_zero(quotient);
    // bn_zero(remainder);
    //printf(" ++ bn_divide ++\n");
    init_zero(quotient, MAX_BIGNUM_WORDS);
    init_zero(remainder, MAX_BIGNUM_WORDS);

    // Copy of the dividend which will be reduced as division proceeds
    BIGNUM temp_dividend;
    init_zero(&temp_dividend, MAX_BIGNUM_WORDS);
    bn_copy(&temp_dividend, dividend); // You might need to ensure proper memory allocation for this copy
    
    // Initialize a temporary variable for subtracted values
    BIGNUM temp_subtract;
    // bn_zero(&temp_subtract);
    init_zero(&temp_subtract, MAX_BIGNUM_WORDS);

    // We need a BIGNUM for 'one' to increment the quotient for each subtraction, assuming we have such function
    BIGNUM one;
    init_zero(&one, MAX_BIGNUM_WORDS);
    bn_set_word(&one, 1);
    
    BIGNUM shifted_divisor;
    BIGNUM shifted_one;

    // Long division algorithm
    while (bn_cmp(&temp_dividend, divisor) >= 0) { // As long as the dividend is greater than or equal to the divisor
        int shift_amount = bn_get_top_bit(&temp_dividend) - bn_get_top_bit(divisor); // calculate needed shift to align most significant bits
        init_zero(&shifted_divisor, MAX_BIGNUM_WORDS);
        bn_lshift_res(&shifted_divisor, divisor, shift_amount); // shift the divisor to the left to align with high bit of dividend
        
        // subtract the shifted divisor from the dividend until no longer possible
        while (bn_cmp(&temp_dividend, &shifted_divisor) >= 0) {

            /*To resolve the issue:

            x Ensure that the bn_lshift_res function correctly shifts one by shift_amount bits to the left. It appears to be not working as intended since shifted_one does not change.

            x Verify the bn_subtract implementation. It correctly zeroed temp_dividend after one subtraction, which may be correct if shifted_divisor was properly aligned and temp_dividend consisted solely of the bit that was aligned to.

            x After fixing the bn_lshift_res issue, if the infinite loop persists, carefully inspect the condition of the outer loop (while (bn_cmp(&temp_dividend, divisor) >= 0)) to ensure that it performs as expected when temp_dividend is zeroed out.

            x Additionally, since you mentioned an "infinity loop issue," if the problem isn't just with the bn_lshift_res function, then there may be other issues with the handling of BIGNUMs that need to be looked at, so all the functions involved in the arithmetic (bn_add, bn_subtract, etc.) should be reviewed and tested individually.

            x Once these operations are confirmed to work independently and produce correct results, they should also work correctly when used within the context of the bn_divide function. Remember to remove the premature return; statement after you have finished debugging to allow the function to finish executing.*/

            bn_print("0 temp_dividend: ", &temp_dividend);
            bn_print("0 shifted_divisor: ", &shifted_divisor);
            bn_subtract(&temp_dividend, &temp_dividend, &shifted_divisor); // subtract the shifted divisor from the dividend
            bn_print("1 temp_dividend: ", &temp_dividend);
            init_zero(&shifted_one, MAX_BIGNUM_WORDS);
            bn_print("2 shifted_one: ", &shifted_one);
            bn_print("2 one: ", &one);
            printf("shift_amount: %d\n", shift_amount);
            bn_lshift_res(&shifted_one, &one, shift_amount); // the part of the quotient we will increment by corresponds to our shift
            bn_print("3 shifted_one: ", &shifted_one);
            bn_print("3 quotient: ", quotient);
            bn_add(quotient, quotient, &shifted_one); // increment the quotient by the appropriate amount
            bn_print("4 quotient: ", quotient);
            printf(" ## bn_divide ##\n");return ; // TODO: Remove this!!
        }
        
        // Continue division until condition is no longer satisfied
    }

    // What remains in temp_dividend at this point is the remainder
    bn_copy(remainder, &temp_dividend);

    // Any necessary cleanup of BIGNUMs would be performed here
    // Make sure to handle any dynamic memory you may have allocated within this function
    printf(" -- bn_divide --\n");
}

__device__ void bn_mod_inverse_fixed_v0(BIGNUM *result, BIGNUM *a, BIGNUM *modulus) {
    
    // Allocate and initialize working variables
    BIGNUM u, v, inv, u1, u3, v1, v3, t1, t3, q;
    // Initialization of these BIGNUMs with proper handling for the CUDA environment is required
    // Zero-initialize all BIGNUMs: u, v, inv, u1, u3, v1, v3, t1, t3, q
    
    /*bn_zero(&u); bn_zero(&v); bn_zero(&inv); 
    bn_zero(&u1); bn_zero(&u3); 
    bn_zero(&v1); bn_zero(&v3); 
    bn_zero(&t1); bn_zero(&t3); 
    bn_zero(&q);*/
    init_zero(&u, MAX_BIGNUM_WORDS);
    init_zero(&v, MAX_BIGNUM_WORDS);
    init_zero(&inv, MAX_BIGNUM_WORDS);
    init_zero(&u1, MAX_BIGNUM_WORDS);
    init_zero(&u3, MAX_BIGNUM_WORDS);
    init_zero(&v1, MAX_BIGNUM_WORDS);
    init_zero(&v3, MAX_BIGNUM_WORDS);
    init_zero(&t1, MAX_BIGNUM_WORDS);
    init_zero(&t3, MAX_BIGNUM_WORDS);
    init_zero(&q, MAX_BIGNUM_WORDS);

    // Set initial values: u1 = 1, u = a, v1 = 0, v = modulus
    bn_set_word(&u1, 1); 
    
    bn_copy(&u, a); 
    // bn_set_word(&v1, 0); -- v1 is already zero-initialized
    bn_copy(&v, modulus);
    unsigned int i = 0; // TODO: remove this
    // The algorithm proceeds to iteratively find the modular inverse
    printf("++ bmi ++\n");    
    // BIGNUM remainder;
    while (!bn_is_zero(&u)) { // While u is not zero
        if (i>10) break; // TODO: remove this
        printf("\n%d", i); // TODO: remove this

        bn_print("u: ", &u);
        bn_print("v: ", &v);
        
        
        bn_divide(&q, &u3, &v, &u); // Divide v by u to get quotient (q) and remainder (u3)
        // bn_divide(&q, remainder, &v, &u);  
        // bn_copy(&u, remainder);

        bn_print("q: ", &q);
        bn_print("u3: ", &u3);

        //printf(" ## bn_mod_inverse TEST ##\n");
        bn_mul(&t3, &q, &v1); // t3 = q * v1
        bn_print("t3: ", &t3);
        bn_print("u1: ", &u1);
        bn_subtract(&t1, &u1, &t3); // t1 = u1 - t3
        bn_print("t1: ", &t1);

        // Shift: (u1, u) <- (v1, v), (v1, v) <- (t1, u3)
        bn_copy(&u1, &v1); bn_copy(&u, &v);
        bn_copy(&v1, &t1); bn_copy(&v, &u3);
        


        // After all calculations for this iteration
        BIGNUM temp_u1, temp_u;
        

        bn_copy(&temp_u1, &v1);
        bn_copy(&temp_u, &v);
        
        bn_copy(&v1, &t1);
        bn_copy(&v, &u3);

        bn_copy(&u1, &temp_u1);
        bn_copy(&u, &temp_u);

        // TODO: remove this ++
        bn_print("u: ", &u);
        bn_print("v: ", &v);
        bn_print("u1: ", &u1);
        bn_print("v1: ", &v1);
        i++;
        // TODO: remove this --
    }
    printf("CC bmi CC\n"); /*
    // Ensure the result is non-negative
    if (bn_is_negative(&v1)) {
        bn_add(&inv, &v1, modulus);
    } else {
        bn_copy(&inv, &v1);
    }

    // Copy the result to the output parameter
    bn_copy(result, &inv);
    */
}

__device__ void bn_abs(BIGNUM *result, BIGNUM *a) {
    // Assuming the BIGNUM structure includes an attribute to indicate the sign (e.g., 'sign')
    // Copy the number from a to result
    // In actual code, this would likely need to loop over each digit and copy them.
    for (int i = 0; i < a->top; ++i) {
        result->d[i] = a->d[i];
    }
    // Ensure result uses the same number of digits as 'a'
    result->top = a->top;

    // Set the sign of the result to be non-negative (0 for positive in many conventions)
    // result->sign = 0;
    result->neg = 0;
}

__device__ void bn_set_signed_word(BIGNUM *r, int64_t value) {
    // Clear any existing value in r.
    // Assuming MAX_BIGNUM_WORDS is defined and represents the maximum size of d[].
    for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
        r->d[i] = 0;
    }

    // Set the sign in r. Assuming the sign is represented by a simple integer where
    // negative numbers have sign = -1 and non-negatives have sign = 0.
    // r->sign = (value < 0) ? -1 : 0;
    r->neg = (value < 0) ? -1 : 0;

    // Store the absolute value of the word in the least significant part of r.
    // Assuming the magnitude can fit in a single 'word' of the BIGNUM data structure.
    // Depending on how BIGNUM is structured, you might need to handle cases where
    // the magnitude of the integer does not fit into a single array element.
    r->d[0] = (value < 0) ? -value : value;

    // Set 'top' to reflect that we're now using the least significant word only.
    // Assuming 'top' is an index of the highest non-zero element.
    r->top = (value != 0) ? 1 : 0;
}

__device__ void bn_swap(BIGNUM *a, BIGNUM *b) {
    // Swap the dynamic parts
    // mp_ptr temp_d = a->d;
    BN_ULONG *temp_d = a->d;
    a->d = b->d;
    b->d = temp_d;
    
    // Swap the scalar components such as top, sign etc.
    int temp_top = a->top;
    a->top = b->top;
    b->top = temp_top;

    int temp_sign = a->neg;
    a->neg = b-> neg;
    b->neg = temp_sign;
    
    // ... Repeat for other scalar elements of BIGNUM as necessary
}

__device__ void bn_gcdext(BIGNUM *g, BIGNUM *s, BIGNUM *t, BIGNUM *a, BIGNUM *b) {
    // Assuming you've defined BIGNUM type, bn_copy, bn_abs_compare, bn_swap, bn_divide, bn_multiply, bn_zero, etc.
    
    // Temporary BIGNUM variables, you would need to provide memory allocation for them
    BIGNUM as, bs, rs, qs, ts;
    /*bn_zero(&as);
    bn_zero(&bs);
    bn_zero(&rs);
    bn_zero(&qs);
    bn_zero(&ts);*/
    init_zero(&as, MAX_BIGNUM_WORDS);
    init_zero(&bs, MAX_BIGNUM_WORDS);
    init_zero(&rs, MAX_BIGNUM_WORDS);
    init_zero(&qs, MAX_BIGNUM_WORDS);
    init_zero(&ts, MAX_BIGNUM_WORDS);
    
    // if (bn_abs_compare(a, b) < 0) {
    if (bn_cmp(a, b) < 0) {
        // Ensure a >= b for the algorithm to work properly
        bn_copy(&as, b);
        bn_copy(&bs, a);
        bn_swap(s, t); // Swap s and t pointers, assuming bn_swap swaps pointers
    } else {
        bn_copy(&as, a);
        bn_copy(&bs, b);
    }
    

    if (bn_is_zero(b)) {
        // Base case: if b is zero, gcd is abs(a) and s is sign(a)
        bn_abs(g, a);
        bn_set_signed_word(s, bn_is_negative(a) ? -1 : 1);
        // bn_zero(t); // t is zero
        init_zero(t, MAX_BIGNUM_WORDS);
        return;
    }
    
    // Extended Euclidean Algorithm iteration
    unsigned int i = 0; // TODO: remove this
    while (!bn_is_zero(&bs)) {
        printf("\n\ni: %d\n", i);
        bn_print("as: ", &as);
        bn_print("bs: ", &bs);
        bn_print("rs: ", &rs);
        bn_print("qs: ", &qs);
        bn_divide(&qs, &rs, &as, &bs); // qs = as / bs, rs = as % bs
        printf("after bn_divide\n");
        bn_print("qs: ", &qs);
        bn_copy(&as, &bs); // Copying bs to as
        bn_print("as: ", &as);
        bn_copy(&bs, &rs); // Copying rs to bs
        bn_print("bs: ", &bs);
        
        // At this point, implement updating logic for s and t using the quotients (qs)
        // This will involve multiplying and subtracting to update s, t
        // This is a non-trivial part and requires careful implementation
        // ...
        i++;
        if (i>2) break; // TODO: remove this
    }
    printf("BN gcd BN\n"); /*
    // Once done with the main loop, set g to as, and if g, s, t are negative, 
    // adjust them to be positive as done in the GMP code
    
    // Make sure to free any resources you've allocated if you're manually managing memory
    */
}

__device__ void bn_mod_inverse_fixed(BIGNUM *inverse, BIGNUM *x, BIGNUM *n) {
    // This assumes bn_gcdext has been implemented which calculates the gcd and the coefficient as gcdext does
    printf("++ bmi ++\n");
    BIGNUM gcd, coefficient;
    
    // You must implement init and zero functions if not already existing
    // Initialize gcd and coefficient
    init_zero(&gcd, MAX_BIGNUM_WORDS);
    init_zero(&coefficient, MAX_BIGNUM_WORDS);
    //printf("FF CONTINUE FROM THIS POINT FF\n"); return; // TODO: remove this CONTINUE FROM THIS POINT
    // Calculate gcd and coefficient where x * coefficient = gcd (mod n)
    bn_gcdext(&gcd, &coefficient, NULL, x, n);
    printf("TEST PASSED: bn_gcdext\n");
    // Check that the GCD is 1, ensuring an inverse exists
    if (!bn_is_one(&gcd)) {
        // return 0; // No inverse exists
        // printf(" -- bmi --\n");
        // bn_init(inverse);
        return;
    }

    // Ensure the coefficient (inverse) is positive
    if (bn_is_negative(&coefficient)) {
        bn_add(inverse, &coefficient, n);
    } else {
        bn_copy(inverse, &coefficient);
    }
    
    // The inverse has been successfully calculated
    //return 1;
    printf(" -- bmi --\n");
    return;
}

__device__ void bn_mod_inverse(BIGNUM *result, BIGNUM *a, BIGNUM *modulus) {
    printf(" ## bn_mod_inverse ##\n");
    // Allocate and initialize working variables
    BIGNUM u, v, inv, u1, u3, v1, v3, t1, t3, q;
    // Initialization of these BIGNUMs with proper handling for the CUDA environment is required
    // Zero-initialize all BIGNUMs: u, v, inv, u1, u3, v1, v3, t1, t3, q
    
    /*bn_zero(&u); bn_zero(&v); bn_zero(&inv); 
    bn_zero(&u1); bn_zero(&u3); 
    bn_zero(&v1); bn_zero(&v3); 
    bn_zero(&t1); bn_zero(&t3); 
    bn_zero(&q);*/
    init_zero(&u, MAX_BIGNUM_WORDS);
    init_zero(&v, MAX_BIGNUM_WORDS);
    init_zero(&inv, MAX_BIGNUM_WORDS);
    init_zero(&u1, MAX_BIGNUM_WORDS);
    init_zero(&u3, MAX_BIGNUM_WORDS);
    init_zero(&v1, MAX_BIGNUM_WORDS);
    init_zero(&v3, MAX_BIGNUM_WORDS);
    init_zero(&t1, MAX_BIGNUM_WORDS);
    init_zero(&t3, MAX_BIGNUM_WORDS);
    init_zero(&q, MAX_BIGNUM_WORDS);
    
    // Set initial values: u1 = 1, u = a, v1 = 0, v = modulus
    bn_set_word(&u1, 1); 
    bn_copy(&u, a); 
    // bn_set_word(&v1, 0); -- v1 is already zero-initialized
    bn_copy(&v, modulus);

    // The algorithm proceeds to iteratively find the modular inverse
    while (!bn_is_zero(&u)) { // While u is not zero
        bn_divide(&q, &u3, &v, &u); // Divide v by u to get quotient (q) and remainder (u3)
        bn_mul(&t3, &q, &v1); // t3 = q * v1
        bn_subtract(&t1, &u1, &t3); // t1 = u1 - t3

        // Shift: (u1, u) <- (v1, v), (v1, v) <- (t1, u3)
        bn_copy(&u1, &v1); bn_copy(&u, &v);
        bn_copy(&v1, &t1); bn_copy(&v, &u3);
    }

    // Ensure the result is non-negative
    if (bn_is_negative(&v1)) {
        bn_add(&inv, &v1, modulus);
    } else {
        bn_copy(&inv, &v1);
    }

    // Copy the result to the output parameter
    bn_copy(result, &inv);

    // Implementation might include clean-up code for all BIGNUM variables 
    // especially if the BIGNUM structure requires deallocation of any allocated memory
}

// CUDA point_add function, based on gmp implementation
__device__ void point_add(
    EC_POINT *result, 
    EC_POINT *p1, 
    EC_POINT *p2, 
    BIGNUM *p, 
    BIGNUM *a
    ) {    // Handle the point at infinity cases
    //printf("A # Result x.d: %f, y.d: %f\n", result->x.d, result->y.d);
    bn_print("point_add init result.x: ", &result->x);
    bn_print("point_add init result.y: ", &result->y);
    bn_print("p1.x: ", &p1->x);
    bn_print("p1.y: ", &p1->y);
    bn_print("p2.x: ", &p2->x);
    bn_print("p2.y: ", &p2->y);
    // bn_print("A result: ", &result.x);
    if (point_is_at_infinity(p1)) {
        printf("point_is_at_infinity(p1)\n");
        //printf("0 # Result x.d: %f, y.d: %f\n", result->x.d, result->y.d);
        //printf("0 # p2 x.d: %f, y.d: %f\n", p2->x.d, p2->y.d);        
        copy_point(result, p2);
        printf("1 # Result x.d: %f, y.d: %f\n", result->x.d, result->y.d);
        return;
    }
    if (point_is_at_infinity(p2)) {
        printf("point_is_at_infinity(p2)\n");
        copy_point(result, p1);
        // printf("copying p1 to result success\n");
        return;
    }

    // Initialize temporary BIGNUMs for calculation
    BIGNUM s, x3, y3, tmp1, tmp2;
    init_zero(&s, MAX_BIGNUM_WORDS);
    init_zero(&x3, MAX_BIGNUM_WORDS);
    init_zero(&y3, MAX_BIGNUM_WORDS);
    init_zero(&tmp1, MAX_BIGNUM_WORDS);
    init_zero(&tmp2, MAX_BIGNUM_WORDS);
    // ... initialization code for BIGNUMs ...
    
    // Case 1: p1.x == p2.x && p1.y != p2.y
    /*if (bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) != 0) {
        printf("bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) != 0\n");
        set_point_at_infinity(result);
        return;
    }*/
    if (bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) == 0) {
        printf("Point Doubling\n");

        // Start point doubling calculation
        // Slope calculation: s = (3 * p1.x^2 + a) / (2 * p1.y)
        // print MAX_BIGNUM_WORDS
        printf("MAX_BIGNUM_WORDS: %d\n", MAX_BIGNUM_WORDS);
        BIGNUM two; 
        /*BN_ULONG d[8];
        two.d = d;
        two.neg = 0;
        two.top = 0;
        two.dmax = MAX_BIGNUM_WORDS;
        two.flags = 0;*/
        // print two params
        // printf("two.top: %d, two.neg: %d\n", two.top, two.neg);        
        init_zero(&two, MAX_BIGNUM_WORDS);
        
        bn_set_word(&two, 2);
        
        bn_mul(&tmp1, &p1->x, &p1->x); // tmp1 = p1.x^2
        
        bn_set_word(&tmp2, 3);
        
        bn_mul(&tmp1, &tmp1, &tmp2);   // tmp1 = 3 * p1.x^2
        
        bn_add(&tmp1, &tmp1, a); // tmp1 = 3 * p1.x^2 + a
        
        bn_mul(&tmp2, &p1->y, &two);    // tmp2 = 2 * p1.y
        bn_mod(&tmp1, p, &tmp1);        // tmp1 = tmp1 mod p
        
        bn_mod(&tmp2, p, &tmp2);        // tmp2 = tmp2 mod p
        
        bn_print("tmp2: ", &tmp2);
        bn_print("p: ", p);
        
        bn_mod_inverse_fixed(&tmp2, p, &tmp2);// tmp2 = (2 * p1.y)^-1 mod p
        printf("== pd ==\n"); /*
        bn_mul(&s, &tmp1, &tmp2);       // s = (3 * p1.x^2 + a) / (2 * p1.y) mod p
        bn_mod(&s, p, &s);
        
        // x3 and y3 calculation:
        bn_mul(&x3, &s, &s);             // x3 = s^2
        bn_sub(&x3, &x3, &p1->x);        
        bn_sub(&x3, &x3, &p1->x);        // x3 = s^2 - 2 * p1.x
        bn_mod(&x3, p, &x3);             // x3 = x3 mod p

        bn_sub(&y3, &p1->x, &x3);        
        bn_mul(&y3, &s, &y3);            // y3 = s * (p1.x - x3)
        bn_sub(&y3, &y3, &p1->y);        // y3 = y3 - p1.y
        bn_mod(&y3, p, &y3);             // y3 = y3 mod p*/
    } else if (bn_cmp(&p1->x, &p2->x) == 0 && bn_cmp(&p1->y, &p2->y) != 0) {
        printf("The points are inverses to one another, returning infinity.\n");
        set_point_at_infinity(result);
        return;
    }

    // Case 2: p1.x != p2.x
    if (bn_cmp(&p1->x, &p2->x) != 0) {
        printf("bn_cmp(&p1->x, &p2->x) != 0\n");
        // Full point addition formula
        bn_sub(&tmp1, &p2->y, &p1->y);
        bn_sub(&tmp2, &p2->x, &p1->x);
        bn_mod(&tmp1, p, &tmp1);
        bn_mod(&tmp2, p, &tmp2);
        bn_mod_inverse(&tmp2, p, &tmp2); // Compute modular inverse
        bn_mul(&s, &tmp1, &tmp2);
        bn_mod(&s, p, &s);

        // ... continue with the point calculation using the BIGNUM operations ...
    } else {
        printf("bn_cmp(&p1->x, &p2->x) == 0\n");
        // Case 3: p1.x == p2.x
        // Point doubling formula
        // ... calculation code for doubling ...

        // Slope calculation:
        // s = (3 * p1.x^2 + a) / (2 * p1.y)

        // x3 and y3 calculation:
        // x3 = s^2 - 2 * p1.x
        // y3 = s * (p1.x - x3) - p1.y
    }

    // Assign the computed coordinates to the result
    //Print result->x.d and result->y.d
    printf("B # Result x.d: %f, y.d: %f\n", result->x.d, result->y.d);
    set_bn(&result->x, &x3);
    set_bn(&result->y, &y3);
    printf("C # Result x.d: %f, y.d: %f\n", result->x.d, result->y.d);

    // Free the temporary variables
    // ... free BIGNUMs ...
}

/*__device__ void point_add_v2(
    EC_POINT *result, 
    const EC_POINT *P, 
    const EC_POINT *Q, 
    const BIGNUM *curve_prime, 
    const BIGNUM *curve_a
) {
    // Handle the point at infinity cases
    if (point_is_at_infinity(P)) {
        copy_point(result, Q);
        return;
    }
    if (point_is_at_infinity(Q)) {
        copy_point(result, P);
        return;
    }
    // ... [other logic before this point] ...

    // Case 3: P.x == Q.x (i.e., point doubling)
    if (bn_cmp(&P->x, &Q->x) == 0) {
        // Perform point doubling calculation...
        BIGNUM s, temp1, temp2;

        // Calculating s as in Python's: s = (3 * P.x^2 + curve_a) * pow(2 * P.y, -1, p)
        // NOTE: You would need to implement functions for squaring, modular inversion,
        //       BIGNUM multiplication/addition, etc.

        // For example:
        bn_square(&temp1, &P->x);        // temp1 = P.x^2
        bn_mul_word(&temp1, &temp1, 3);  // temp1 = 3 * P.x^2
        bn_add(&temp1, &temp1, curve_a); // temp1 = 3 * P.x^2 + curve_a
        bn_lshift(&temp2, &P->y, 1);    // temp2 = 2 * P.y

        // Calculate the modular inverse of 2*P.y, storing in temp2
        bn_mod_inverse(&temp2, &temp2, curve_prime);

        // Multiply the inverse by (3 * P.x^2 + curve_a), storing result in s
        bn_mul(&s, &temp1, &temp2);
        bn_mod(&s, &s, curve_prime);

        // Add the debug print after calculating s
        bn_print("p: ", curve_prime);
        bn_print("s: ", &s);

        // ... [rest of the code to compute the resulting x and y using s] ...
    }
    // ... [rest of the function] ...
}*/

__device__ void bignum_to_bit_array(const BIGNUM *n, unsigned int *bits) {
    int index = 0;
    for (int i = 0; i < n->top; ++i) {
        BN_ULONG word = n->d[i];
        for (int j = 0; j < 32; ++j) {  // Assuming BN_ULONG is 32 bits
            bits[index++] = (word >> j) & 1;
        }
    }
}

__device__ void init_point_at_infinity(EC_POINT *P) {
    // For the x and y coordinates of P, we'll set the 'top' to 0,
    // which is our chosen convention for representing the point at infinity.

    P->x.top = 0; // No valid 'words' in the BIGNUM representing x
    P->y.top = 0; // No valid 'words' in the BIGNUM representing y

    // If 'd' arrays have been allocated, set them to zero as well.
    // memset could potentially be used for this if available and if 'd' is allocated.
    
    for (int i = 0; i < P->x.dmax; ++i) {
        P->x.d[i] = 0;
    }
    for (int i = 0; i < P->y.dmax; ++i) {
        P->y.d[i] = 0;
    }
    
    // Alternatively, if you use flags or other conventions for points at infinity,
    // set them accordingly here.
}