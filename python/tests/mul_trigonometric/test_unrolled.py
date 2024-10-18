import math

def my_asin(x, depth=2):
    # arcsin(x) = x + (1/2)(x³/3) + (1·3/2·4)(x⁵/5) + (1·3·5/2·4·6)(x⁷/7) + ...
    arcsin = x
    for i in range(1, depth):
        arcsin += (math.prod([2 * i - 1 for i in range(1, i + 1)]) / math.prod([2 * i for i in range(1, i + 1)]) * x**(2 * i + 1)) / (2 * i + 1)
    return arcsin

def my_tan(x, depth=10):
    # Coefficients for the first few terms of the series
    coefficients = [1, 1/3, 2/15, 17/315, 62/2835]
    
    # Extend coefficients if depth is greater than 5
    if depth > 5:
        for n in range(5, depth):
            # Calculate Bernoulli numbers (this is a simplified approach)
            b = [1] + [0] * (2*n)
            for m in range(1, 2*n + 1):
                b[m] = sum(math.comb(m, k) * b[k] / (m - k + 1) for k in range(m)) / m
            
            # Calculate coefficient
            coeff = (2**(2*n) * (2**(2*n) - 1) * abs(b[2*n])) / math.factorial(2*n)
            coefficients.append(coeff)
    
    # Calculate the series
    tan_x = 0
    for n, coeff in enumerate(coefficients[:depth]):
        tan_x += coeff * x**(2*n + 1)
    
    return tan_x

def mul_trigonometric(a, b):
    # product = a / tg( arcsin(1/sqrt(1**2 + b**2)) )
    # product = a / (math.tan(math.asin(1 / math.sqrt(1 + b**2))))
    x = 1 / math.sqrt(1 + b**2)
    # product = a / math.tan(math.asin(x))
    x = my_asin(x)
    # product = a / math.tan(x)
    x = my_tan(x)
    product = a / x
    # ceil
    # product = math.ceil(product)
    return product
    

def main():
    a = 4
    b = 3
    print("a: ", a)
    print("b: ", b)
    print(f"Product: {mul_trigonometric(a, b)}")


if __name__ == '__main__':
    main()