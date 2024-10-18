import math

def mul_trigonometric(a, b):
    # product = a / tg( arcsin(1/sqrt(1**2 + b**2)) )
    product = a / (math.tan(math.asin(1 / math.sqrt(1 + b**2))))
    return product
    

def main():
    a = 4
    b = 3
    print("a: ", a)
    print("b: ", b)
    print(f"Product: {mul_trigonometric(a, b)}")


if __name__ == '__main__':
    main()