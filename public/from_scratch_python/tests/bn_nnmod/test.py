class BIGNUM:
    def __init__(self, d=None, top=0, dmax=0, neg=0, flags=0):
        self.d = d if d else []
        self.top = top
        self.dmax = dmax
        self.neg = neg
        self.flags = flags

def bn_print(msg, a):
    print(msg, end="")
    if a.neg:
        print("-", end="")
    for i in range(a.top - 1, -1, -1):
        print(f"{a.d[i]:016x}", end=" ")
    print()

def bn_cmp(a, b):
    if a.neg != b.neg:
        return -1 if a.neg else 1

    if a.top != b.top:
        return 1 if a.top > b.top else -1

    for i in range(a.top - 1, -1, -1):
        if a.d[i] != b.d[i]:
            return 1 if a.d[i] > b.d[i] else -1

    return 0

def bn_copy(dst, src):
    if dst.dmax < src.top:
        dst.d = src.d.copy()
        dst.dmax = src.top
    else:
        dst.d[:src.top] = src.d[:src.top]

    dst.top = src.top
    dst.neg = src.neg

def bn_sub(r, a, b):
    max_top = max(a.top, b.top)

    if r.dmax < max_top:
        r.d = [0] * max_top
        r.dmax = max_top

    borrow = 0
    for i in range(max_top):
        ai = a.d[i] if i < a.top else 0
        bi = b.d[i] if i < b.top else 0
        diff = ai - bi - borrow
        borrow = 1 if diff < 0 else 0
        r.d[i] = diff & 0xFFFFFFFFFFFFFFFF

    r.top = max_top
    r.neg = borrow

    while r.top > 0 and r.d[r.top - 1] == 0:
        r.top -= 1

def bn_add(r, a, b):
    max_top = max(a.top, b.top)

    if r.dmax < max_top + 1:
        r.d = [0] * (max_top + 1)
        r.dmax = max_top + 1

    carry = 0
    for i in range(max_top):
        ai = a.d[i] if i < a.top else 0
        bi = b.d[i] if i < b.top else 0
        sum = carry + ai + bi
        r.d[i] = sum & 0xFFFFFFFFFFFFFFFF
        carry = sum >> 64

    if carry:
        r.d[max_top] = carry
        r.top = max_top + 1
    else:
        r.top = max_top

    r.neg = 0

def bn_mod(r, a, m):
    tmp = BIGNUM(d=a.d.copy(), top=a.top, dmax=a.top, neg=a.neg)

    while bn_cmp(tmp, m) >= 0:
        bn_sub(tmp, tmp, m)

    bn_copy(r, tmp)

def bn_nnmod(r, a, m):
    if m.top == 0:
        raise ValueError("Division by zero")

    if r is m:
        raise ValueError("BN_nnmod: ERR_R_PASSED_INVALID_ARGUMENT")

    bn_mod(r, a, m)

    if r.neg:
        bn_add(r, r, m)

# Example usage
a = BIGNUM(d=[0x2d5971788066012b, 0xb9df77e2c7a41dba, 0x052181e3741e8338, 0x78e39ee6aa40ef8e], top=4, dmax=4, neg=1)
n = BIGNUM(d=[0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f], top=4, dmax=4, neg=0)
r = BIGNUM(d=[0] * 4, top=4, dmax=4, neg=0)

bn_print("a = ", a)
bn_print("n = ", n)

bn_nnmod(r, a, n)

bn_print("r = ", r)
