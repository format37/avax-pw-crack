#include <stdio.h>
#include <stdlib.h>

// Elliptic Curve constants for y^2 = x^3 + ax + b over finite field F_p
const int P = 17;
const int a = 2;
const int b = 2;

// CUDA device function to compute modular inverse using Extended Euclidean Algorithm
__device__ int modInverse(int a, int p) {
    int t = 0, newt = 1;
    int r = p, newr = a;
    while (newr != 0) {
        int quotient = r / newr;
        int tmp;
        
        tmp = newt;
        newt = t - quotient * newt;
        t = tmp;

        tmp = newr;
        newr = r - quotient * newr;
        r = tmp;
    }
    if (r > 1) return -1; // a is not invertible
    if (t < 0) t += p;
    return t;
}

// CUDA device function to compute modulo, correctly handling negative inputs
__device__ int mod(int x, int m) {
    int r = x % m;
    return r < 0 ? r + m : r;
}

// CUDA kernel for point addition and doubling calculation
__global__ void pointAdditionKernel(int *Px, int *Py, int *Qx, int *Qy, int *Rx, int *Ry) {
    int tid = threadIdx.x;

    if (tid == 0) {  // Thread 0 for P + Q
        int x1 = Px[0];
        int y1 = Py[0];
        int x2 = Qx[0];
        int y2 = Qy[0];

        // Handle special cases
        if (x1 == x2 && y1 == y2) { // Doubling case
            int numerator = mod(3 * x1 * x1 + a, P);
            int denominator = mod(2 * y1, P);
            int inv = modInverse(denominator, P);
            if (inv == -1) { // Division by zero case
                Rx[0] = -1;
                Ry[0] = -1;
                return;
            }
            int m = mod(numerator * inv, P);
            
            Rx[0] = mod(m * m - 2 * x1, P);
            Ry[0] = mod(m * (x1 - Rx[0]) - y1, P);
        } else {
            if (x1 == x2 && (y1 + y2) % P == 0) {  // Points are inverses on a vertical line
                Rx[0] = -1;
                Ry[0] = -1;
            } else {  // General case
                int numerator = mod(y2 - y1, P);
                int denominator = mod(x2 - x1, P);
                int inv = modInverse(denominator, P);
                if (inv == -1) { // Division by zero case
                    Rx[0] = -1;
                    Ry[0] = -1;
                    return;
                }
                int m = mod(numerator * inv, P);
                Rx[0] = mod(m * m - x1 - x2, P);
                Ry[0] = mod(m * (x1 - Rx[0]) - y1, P);
            }
        }
    }
    else if (tid == 1) {  // Thread 1 for P + P (doubling)
        int x1 = Px[0];
        int y1 = Py[0];

        if (y1 == 0) {  // Doubling leads to infinity
            Rx[1] = -1;
            Ry[1] = -1;
            return;
        }

        int numerator = mod(3 * x1 * x1 + a, P);
        int denominator = mod(2 * y1, P);
        int inv = modInverse(denominator, P);
        if (inv == -1) { // Division by zero case
            Rx[1] = -1;
            Ry[1] = -1;
            return;
        }
        int m = mod(numerator * inv, P);

        Rx[1] = mod(m * m - 2 * x1, P);
        Ry[1] = mod(m * (x1 - Rx[1]) - y1, P);
    }
}

void runTestCases() {
    FILE *file = fopen("cases.txt", "r");
    if (!file) {
        fprintf(stderr, "Could not open cases.txt\n");
        exit(1);
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        // Parse each line in cases.txt
        int x1, y1, x2, y2, expected_rx, expected_ry, expected_rdx, expected_rdy;
        sscanf(line, "%d %d %d %d %d %d %d %d",
               &x1, &y1, &x2, &y2, &expected_rx, &expected_ry, &expected_rdx, &expected_rdy);

        int h_Px[1] = {x1};
        int h_Py[1] = {y1};
        int h_Qx[1] = {x2};
        int h_Qy[1] = {y2};
        int h_Rx[2] = {0};
        int h_Ry[2] = {0};

        int *d_Px, *d_Py, *d_Qx, *d_Qy, *d_Rx, *d_Ry;

        cudaMalloc((void**)&d_Px, sizeof(int));
        cudaMalloc((void**)&d_Py, sizeof(int));
        cudaMalloc((void**)&d_Qx, sizeof(int));
        cudaMalloc((void**)&d_Qy, sizeof(int));
        cudaMalloc((void**)&d_Rx, 2 * sizeof(int));
        cudaMalloc((void**)&d_Ry, 2 * sizeof(int));

        cudaMemcpy(d_Px, h_Px, sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_Py, h_Py, sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_Qx, h_Qx, sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_Qy, h_Qy, sizeof(int), cudaMemcpyHostToDevice);

        pointAdditionKernel<<<1, 2>>>(d_Px, d_Py, d_Qx, d_Qy, d_Rx, d_Ry);
        cudaDeviceSynchronize();

        cudaMemcpy(h_Rx, d_Rx, 2 * sizeof(int), cudaMemcpyDeviceToHost);
        cudaMemcpy(h_Ry, d_Ry, 2 * sizeof(int), cudaMemcpyDeviceToHost);

        // Test results with expected values
        int add_correct = ((h_Rx[0] == expected_rx || (h_Rx[0] == -1 && expected_rx == -1)) &&
                           (h_Ry[0] == expected_ry || (h_Ry[0] == -1 && expected_ry == -1)));

        int dbl_correct = ((h_Rx[1] == expected_rdx || (h_Rx[1] == -1 && expected_rdx == -1)) &&
                           (h_Ry[1] == expected_rdy || (h_Ry[1] == -1 && expected_rdy == -1)));

        printf("%d %d %d %d -> Addition %s, Doubling %s\n",
               x1, y1, x2, y2,
               add_correct ? "PASS" : "FAIL",
               dbl_correct ? "PASS" : "FAIL");

        cudaFree(d_Px);
        cudaFree(d_Py);
        cudaFree(d_Qx);
        cudaFree(d_Qy);
        cudaFree(d_Rx);
        cudaFree(d_Ry);
    }

    fclose(file);
}

int main() {
    runTestCases();
    return 0;
}
