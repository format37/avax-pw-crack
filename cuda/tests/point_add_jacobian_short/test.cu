#include <stdio.h>
#include <stdlib.h>
#include <cuda.h>

/**
 * Reads elliptic curve test cases from 'cases.txt' and performs point addition
 * and point doubling using correct formulas in Jacobian coordinates.
 *
 * The test cases have the following format:
 * Px Py Qx Qy (P+Q)x (P+Q)y (P+P)x (P+P)y
 * where P and Q are points on the elliptic curve.
 */

// Elliptic Curve constants for y^2 = x^3 + ax + b over finite field F_p
const int P = 17; // Prime modulus
const int a = 2;  // Elliptic curve parameter 'a'

// Function to compute modular inverse using Extended Euclidean Algorithm
__host__ __device__ int modInverse(int a, int p) {
    int t = 0, newt = 1;
    int r = p, newr = a % p;
    while (newr != 0) {
        int quotient = r / newr;
        int temp;

        temp = t;
        t = newt;
        newt = temp - quotient * newt;

        temp = r;
        r = newr;
        newr = temp - quotient * newr;
    }
    if (r > 1) return -1; // a is not invertible
    if (t < 0) t += p;
    return t;
}

// Function to compute modulo, correctly handling negative inputs
__host__ __device__ int mod(int x, int m) {
    int r = x % m;
    return r < 0 ? r + m : r;
}

// CUDA kernel for point addition and doubling calculation using Jacobian coordinates
__global__ void jacobianPointAdditionKernel(int *X1, int *Y1, int *Z1, int *X2, int *Y2, int *Z2, int *RX, int *RY, int *RZ) {
    int tid = threadIdx.x;

    if (tid == 0) { // Point addition P + Q
        // Check if P is at infinity
        if (Z1[0] == 0) {
            // Return Q
            RX[0] = X2[0];
            RY[0] = Y2[0];
            RZ[0] = Z2[0];
            return;
        }
        // Check if Q is at infinity
        if (Z2[0] == 0) {
            // Return P
            RX[0] = X1[0];
            RY[0] = Y1[0];
            RZ[0] = Z1[0];
            return;
        }

        // Calculations
        int U1 = mod(X1[0] * mod(Z2[0] * Z2[0], P), P);
        int U2 = mod(X2[0] * mod(Z1[0] * Z1[0], P), P);
        int S1 = mod(Y1[0] * mod(Z2[0] * Z2[0] * Z2[0], P), P);
        int S2 = mod(Y2[0] * mod(Z1[0] * Z1[0] * Z1[0], P), P);

        int H = mod(U2 - U1, P);
        int r = mod(S2 - S1, P);

        if (H == 0) {
            if (r == 0) {
                // P == Q, perform doubling
                if (mod(Y1[0] * Z1[0], P) == 0) {
                    // Point at infinity
                    RX[0] = 0;
                    RY[0] = 1;
                    RZ[0] = 0;
                } else {
                    // Doubling formulas
                    int XX = mod(X1[0] * X1[0], P);
                    int YY = mod(Y1[0] * Y1[0], P);
                    int YYYY = mod(YY * YY, P);
                    int ZZ = mod(Z1[0] * Z1[0], P);
                    int S = mod(4 * X1[0] * YY, P);
                    int M = mod(3 * XX + a * mod(ZZ * ZZ, P), P);
                    int T = mod(M * M - 2 * S, P);
                    RX[0] = T;
                    RY[0] = mod(M * (S - T) - 8 * YYYY, P);
                    RZ[0] = mod(2 * Y1[0] * Z1[0], P);
                }
                return;
            } else {
                // P == -Q, result is point at infinity
                RX[0] = 0;
                RY[0] = 1;
                RZ[0] = 0;
                return;
            }
        } else {
            // P != Q, perform point addition
            int H2 = mod(H * H, P);
            int H3 = mod(H * H2, P);
            int U1H2 = mod(U1 * H2, P);
            int X3 = mod(r * r - H3 - 2 * U1H2, P);
            int Y3 = mod(r * (U1H2 - X3) - S1 * H3, P);
            int Z3 = mod(H * Z1[0] * Z2[0], P);
            RX[0] = X3;
            RY[0] = Y3;
            RZ[0] = Z3;
            return;
        }
    } else if (tid == 1) { // Point doubling P + P
        // Check if point is at infinity
        if (Z1[1] == 0 || Y1[1] == 0) {
            // Point at infinity
            RX[1] = 0;
            RY[1] = 1;
            RZ[1] = 0;
            return;
        } else {
            // Doubling formulas
            int XX = mod(X1[1] * X1[1], P);
            int YY = mod(Y1[1] * Y1[1], P);
            int YYYY = mod(YY * YY, P);
            int ZZ = mod(Z1[1] * Z1[1], P);
            int S = mod(4 * X1[1] * YY, P);
            int M = mod(3 * XX + a * mod(ZZ * ZZ, P), P);
            int T = mod(M * M - 2 * S, P);
            RX[1] = T;
            RY[1] = mod(M * (S - T) - 8 * YYYY, P);
            RZ[1] = mod(2 * Y1[1] * Z1[1], P);
            return;
        }
    }
}

void runTestCasesJacobian() {
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

        int h_X1[2] = {x1, x1};
        int h_Y1[2] = {y1, y1};
        int h_Z1[2] = {1, 1};  // Z = 1 for affine inputs
        int h_X2[2] = {x2, x2};
        int h_Y2[2] = {y2, y2};
        int h_Z2[2] = {1, 1};
        int h_RX[2] = {0};
        int h_RY[2] = {0};
        int h_RZ[2] = {0};

        int *d_X1, *d_Y1, *d_Z1, *d_X2, *d_Y2, *d_Z2, *d_RX, *d_RY, *d_RZ;

        cudaMalloc((void**)&d_X1, 2 * sizeof(int));
        cudaMalloc((void**)&d_Y1, 2 * sizeof(int));
        cudaMalloc((void**)&d_Z1, 2 * sizeof(int));
        cudaMalloc((void**)&d_X2, 2 * sizeof(int));
        cudaMalloc((void**)&d_Y2, 2 * sizeof(int));
        cudaMalloc((void**)&d_Z2, 2 * sizeof(int));
        cudaMalloc((void**)&d_RX, 2 * sizeof(int));
        cudaMalloc((void**)&d_RY, 2 * sizeof(int));
        cudaMalloc((void**)&d_RZ, 2 * sizeof(int));

        cudaMemcpy(d_X1, h_X1, 2 * sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_Y1, h_Y1, 2 * sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_Z1, h_Z1, 2 * sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_X2, h_X2, 2 * sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_Y2, h_Y2, 2 * sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_Z2, h_Z2, 2 * sizeof(int), cudaMemcpyHostToDevice);

        jacobianPointAdditionKernel<<<1, 2>>>(d_X1, d_Y1, d_Z1, d_X2, d_Y2, d_Z2, d_RX, d_RY, d_RZ);
        cudaDeviceSynchronize();

        cudaMemcpy(h_RX, d_RX, 2 * sizeof(int), cudaMemcpyDeviceToHost);
        cudaMemcpy(h_RY, d_RY, 2 * sizeof(int), cudaMemcpyDeviceToHost);
        cudaMemcpy(h_RZ, d_RZ, 2 * sizeof(int), cudaMemcpyDeviceToHost);

        // Convert back from Jacobian to affine coordinates for comparison
        int rx_affine, ry_affine;
        if (h_RZ[0] == 0) {
            rx_affine = -1; // Point at infinity
            ry_affine = -1;
        } else {
            int z_inv = modInverse(h_RZ[0], P);
            int z_inv2 = mod(z_inv * z_inv, P);
            int z_inv3 = mod(z_inv2 * z_inv, P);
            rx_affine = mod(h_RX[0] * z_inv2, P);
            ry_affine = mod(h_RY[0] * z_inv3, P);
        }

        int rdx_affine, rdy_affine;
        if (h_RZ[1] == 0) {
            rdx_affine = -1; // Point at infinity
            rdy_affine = -1;
        } else {
            int z_inv = modInverse(h_RZ[1], P);
            int z_inv2 = mod(z_inv * z_inv, P);
            int z_inv3 = mod(z_inv2 * z_inv, P);
            rdx_affine = mod(h_RX[1] * z_inv2, P);
            rdy_affine = mod(h_RY[1] * z_inv3, P);
        }

        // Test results with expected values
        int add_correct = ((rx_affine == expected_rx || (rx_affine == -1 && expected_rx == -1)) &&
                           (ry_affine == expected_ry || (ry_affine == -1 && expected_ry == -1)));

        int dbl_correct = ((rdx_affine == expected_rdx || (rdx_affine == -1 && expected_rdx == -1)) &&
                           (rdy_affine == expected_rdy || (rdy_affine == -1 && expected_rdy == -1)));

        printf("P=(%d, %d), Q=(%d, %d) -> Addition %s, Doubling %s\n",
               x1, y1, x2, y2,
               add_correct ? "PASS" : "FAIL",
               dbl_correct ? "PASS" : "FAIL");

        cudaFree(d_X1);
        cudaFree(d_Y1);
        cudaFree(d_Z1);
        cudaFree(d_X2);
        cudaFree(d_Y2);
        cudaFree(d_Z2);
        cudaFree(d_RX);
        cudaFree(d_RY);
        cudaFree(d_RZ);
    }

    fclose(file);
}

int main() {
    runTestCasesJacobian();
    return 0;
}
