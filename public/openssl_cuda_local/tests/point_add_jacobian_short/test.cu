#include <stdio.h>
#include <stdlib.h>

// Elliptic Curve constants for y^2 = x^3 + ax + b over finite field F_p
const int P = 17;
const int a = 2;

// Function to compute modular inverse using Extended Euclidean Algorithm
__host__ __device__ int modInverse(int a, int p) {
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

// Function to compute modulo, correctly handling negative inputs
__host__ __device__ int mod(int x, int m) {
    int r = x % m;
    return r < 0 ? r + m : r;
}

// CUDA kernel for point addition and doubling calculation using Jacobian coordinates
__global__ void jacobianPointAdditionKernel(int *X1, int *Y1, int *Z1, int *X2, int *Y2, int *Z2, int *RX, int *RY, int *RZ) {
    int tid = threadIdx.x;

    if (tid == 0) { // Point addition P + Q
        // Convert Q to the same scale as P
        int U1 = mod(X1[0] * Z2[0] * Z2[0], P);  // X1 * Z2^2
        int U2 = mod(X2[0] * Z1[0] * Z1[0], P);  // X2 * Z1^2
        int S1 = mod(Y1[0] * Z2[0] * Z2[0] * Z2[0], P); // Y1 * Z2^3
        int S2 = mod(Y2[0] * Z1[0] * Z1[0] * Z1[0], P); // Y2 * Z1^3

        if (U1 == U2 && S1 == S2) { // P == Q -> doubling
            if (Y1[0] == 0) { // Check for infinity
                RX[0] = 0;
                RY[0] = 0;
                RZ[0] = 0;
                return;
            }

            int XX = mod(X1[0] * X1[0], P); // X1^2
            int ZZ = mod(Z1[0] * Z1[0], P); // Z1^2
            int W = mod(3 * XX + a * ZZ, P); // 3*X1^2 + a*Z1^4
            int S = mod(4 * X1[0] * Y1[0] * Y1[0], P); // 4*X1*Y1^2
            int B = mod(8 * Y1[0] * Y1[0] * Y1[0] * Y1[0], P); // 8*Y1^4

            RX[0] = mod(W * W - 2 * S, P); // Rx = W^2 - 2*S
            RY[0] = mod(W * (S - RX[0]) - B, P); // Ry = W*(S - RX) - B
            RZ[0] = mod(2 * Y1[0] * Z1[0], P); // Rz = 2*Y1*Z1
        } else { // P != Q
            int H = mod(U2 - U1, P);
            int R = mod(S2 - S1, P);

            if (H == 0) { // Points are inverses of each other
                RX[0] = 0;
                RY[0] = 0;
                RZ[0] = 0;
                return;
            }

            int HH = mod(H * H, P);
            int HHH = mod(H * HH, P);
            int U1HH = mod(U1 * HH, P);

            RX[0] = mod(R * R - HHH - 2 * U1HH, P);
            RY[0] = mod(R * (U1HH - RX[0]) - S1 * HHH, P);
            RZ[0] = mod(H * Z1[0] * Z2[0], P);
        }
    } else if (tid == 1) { // Point doubling P + P
        if (Y1[0] == 0) { // Check for infinity
            RX[1] = 0;
            RY[1] = 0;
            RZ[1] = 0;
            return;
        }

        // Corrected Doubling calculations
        int XX = mod(X1[0] * X1[0], P); // X1^2
        int ZZ = mod(Z1[0] * Z1[0], P); // Z1^2
        int W = mod(3 * XX + a * ZZ, P); // 3*X1^2 + a*Z1^4
        int S = mod(4 * X1[0] * Y1[0] * Y1[0], P); // 4*X1*Y1^2
        int B = mod(8 * Y1[0] * Y1[0] * Y1[0] * Y1[0], P); // 8*Y1^4

        RX[1] = mod(W * W - 2 * S, P); // Rx = W^2 - 2*S
        RY[1] = mod(W * (S - RX[1]) - B, P); // Ry = W*(S - RX) - B
        RZ[1] = mod(2 * Y1[0] * Z1[0], P); // Rz = 2*Y1*Z1
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
        int h_Z1[2] = {1, 1};  // Jacobian coordinates (X, Y, Z); Z = 1 for affine inputs
        int h_X2[2] = {x2, x2};
        int h_Y2[2] = {y2, y2};
        int h_Z2[2] = {1, 1};  // Same
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
        int z_inv = modInverse(h_RZ[0], P);
        int rx_affine = mod(h_RX[0] * z_inv * z_inv, P);
        int ry_affine = mod(h_RY[0] * z_inv * z_inv * z_inv, P);

        int z_inv_dbl = modInverse(h_RZ[1], P);
        int rdx_affine = mod(h_RX[1] * z_inv_dbl * z_inv_dbl, P);
        int rdy_affine = mod(h_RY[1] * z_inv_dbl * z_inv_dbl * z_inv_dbl, P);

        // Test results with expected values
        int add_correct = ((rx_affine == expected_rx || (rx_affine == -1 && expected_rx == -1)) &&
                           (ry_affine == expected_ry || (ry_affine == -1 && expected_ry == -1)));

        int dbl_correct = ((rdx_affine == expected_rdx || (rdx_affine == -1 && expected_rdx == -1)) &&
                           (rdy_affine == expected_rdy || (rdy_affine == -1 && expected_rdy == -1)));

        printf("%d %d %d %d -> Addition %s, Doubling %s\n",
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