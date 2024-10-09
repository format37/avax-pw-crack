#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

// #define use_openssl

#define MAX_LINE_LENGTH 1024
#define MAX_TEST_CASES 1000
#define HEX_STRING_LENGTH 65  // 64 characters for 256-bit number + null terminator

typedef struct {
    char Px[HEX_STRING_LENGTH], Py[HEX_STRING_LENGTH], Qx[HEX_STRING_LENGTH], Qy[HEX_STRING_LENGTH];
    char ExpectedAddX[HEX_STRING_LENGTH], ExpectedAddY[HEX_STRING_LENGTH];
    char ExpectedDoubleX[HEX_STRING_LENGTH], ExpectedDoubleY[HEX_STRING_LENGTH];
} TestCase;

// Structure to represent a point in Jacobian coordinates
typedef struct {
    BIGNUM *X;
    BIGNUM *Y;
    BIGNUM *Z;
} EC_POINT_JACOBIAN;

// Function to initialize an EC_POINT_JACOBIAN
void EC_POINT_Jacobian_new(EC_POINT_JACOBIAN *point) {
    point->X = BN_new();
    point->Y = BN_new();
    point->Z = BN_new();
}

// Function to free an EC_POINT_JACOBIAN
void EC_POINT_Jacobian_free(EC_POINT_JACOBIAN *point) {
    BN_free(point->X);
    BN_free(point->Y);
    BN_free(point->Z);
}

// Function to initialize an EC_POINT from hex strings
void init_point_from_hex(EC_GROUP *group, EC_POINT *point, const char *x_hex, const char *y_hex, BN_CTX *ctx) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BN_hex2bn(&x, x_hex);
    BN_hex2bn(&y, y_hex);
    EC_POINT_set_affine_coordinates_GFp(group, point, x, y, ctx);
    BN_free(x);
    BN_free(y);
}

// Convert an affine point to Jacobian coordinates
void affine_to_jacobian(const EC_GROUP *group, const EC_POINT *P, EC_POINT_JACOBIAN *R, BN_CTX *ctx) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx);
    BN_copy(R->X, x);
    BN_copy(R->Y, y);
    BN_one(R->Z); // Z = 1

    BN_free(x);
    BN_free(y);
}

// Convert a Jacobian point to affine coordinates
void jacobian_to_affine(const EC_GROUP *group, const EC_POINT_JACOBIAN *P, EC_POINT *R, BN_CTX *ctx) {
    if (BN_is_zero(P->Z)) {
        // Point at infinity
        EC_POINT_set_to_infinity(group, R);
        return;
    }

    BIGNUM *Z_inv = BN_new();
    BIGNUM *Z_inv2 = BN_new();
    BIGNUM *Z_inv3 = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *p = BN_new();

    EC_GROUP_get_curve_GFp(group, p, NULL, NULL, ctx);

    BN_mod_inverse(Z_inv, P->Z, p, ctx);
    BN_mod_sqr(Z_inv2, Z_inv, p, ctx);
    BN_mod_mul(Z_inv3, Z_inv2, Z_inv, p, ctx);

    BN_mod_mul(x, P->X, Z_inv2, p, ctx);
    BN_mod_mul(y, P->Y, Z_inv3, p, ctx);

    EC_POINT_set_affine_coordinates_GFp(group, R, x, y, ctx);

    BN_free(Z_inv);
    BN_free(Z_inv2);
    BN_free(Z_inv3);
    BN_free(x);
    BN_free(y);
    BN_free(p);
}

// Perform point addition in Jacobian coordinates
void jacobian_point_add(
    const EC_GROUP *group,
    EC_POINT_JACOBIAN *result,
    const EC_POINT_JACOBIAN *P,
    const EC_POINT_JACOBIAN *Q,
    BN_CTX *ctx
) {
    BIGNUM *p = BN_new();
    EC_GROUP_get_curve_GFp(group, p, NULL, NULL, ctx);

    // Handle special cases
    if (BN_is_zero(P->Z)) {
        BN_copy(result->X, Q->X);
        BN_copy(result->Y, Q->Y);
        BN_copy(result->Z, Q->Z);
        BN_free(p);
        return;
    }
    if (BN_is_zero(Q->Z)) {
        BN_copy(result->X, P->X);
        BN_copy(result->Y, P->Y);
        BN_copy(result->Z, P->Z);
        BN_free(p);
        return;
    }

    // Initialize temporary variables
    BIGNUM *U1 = BN_new();
    BIGNUM *U2 = BN_new();
    BIGNUM *S1 = BN_new();
    BIGNUM *S2 = BN_new();
    BIGNUM *H = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *H_squared = BN_new();
    BIGNUM *H_cubed = BN_new();
    BIGNUM *U1_H_squared = BN_new();
    BIGNUM *tmp = BN_new();

    // U1 = X1 * Z2^2 mod p
    BN_mod_sqr(tmp, Q->Z, p, ctx);
    BN_mod_mul(U1, P->X, tmp, p, ctx);

    // U2 = X2 * Z1^2 mod p
    BN_mod_sqr(tmp, P->Z, p, ctx);
    BN_mod_mul(U2, Q->X, tmp, p, ctx);

    // S1 = Y1 * Z2^3 mod p
    BN_mod_mul(tmp, Q->Z, tmp, p, ctx); // tmp = Z2^3
    BN_mod_mul(S1, P->Y, tmp, p, ctx);

    // S2 = Y2 * Z1^3 mod p
    BN_mod_sqr(tmp, P->Z, p, ctx);
    BN_mod_mul(tmp, P->Z, tmp, p, ctx); // tmp = Z1^3
    BN_mod_mul(S2, Q->Y, tmp, p, ctx);

    // H = U2 - U1 mod p
    BN_mod_sub(H, U2, U1, p, ctx);

    // r = S2 - S1 mod p
    BN_mod_sub(r, S2, S1, p, ctx);

    if (BN_is_zero(H)) {
        if (BN_is_zero(r)) {
            // Point doubling
            // Implement jacobian_point_double here or call existing function
            // For brevity, setting result to P (should actually perform doubling)
            // In practice, you should implement jacobian_point_double similarly
            BN_copy(result->X, P->X);
            BN_copy(result->Y, P->Y);
            BN_copy(result->Z, P->Z);
        } else {
            // Result is point at infinity
            BN_zero(result->X);
            BN_zero(result->Y);
            BN_zero(result->Z);
        }
        goto cleanup;
    }

    // Compute H_squared = H^2
    BN_mod_sqr(H_squared, H, p, ctx);

    // Compute H_cubed = H^3
    BN_mod_mul(H_cubed, H_squared, H, p, ctx);

    // Compute U1_H_squared = U1 * H_squared
    BN_mod_mul(U1_H_squared, U1, H_squared, p, ctx);

    // Compute X3 = r^2 - H^3 - 2 * U1_H_squared
    BN_mod_sqr(tmp, r, p, ctx); // tmp = r^2
    BN_mod_sub(tmp, tmp, H_cubed, p, ctx);
    BN_mod_sub(tmp, tmp, U1_H_squared, p, ctx);
    BN_mod_sub(result->X, tmp, U1_H_squared, p, ctx);

    // Compute Y3 = r * (U1_H_squared - X3) - S1 * H_cubed
    BN_mod_sub(tmp, U1_H_squared, result->X, p, ctx);
    BN_mod_mul(tmp, tmp, r, p, ctx);
    BN_mod_mul(S1, S1, H_cubed, p, ctx);
    BN_mod_sub(result->Y, tmp, S1, p, ctx);

    // Compute Z3 = H * Z1 * Z2
    BN_mod_mul(tmp, P->Z, Q->Z, p, ctx);
    BN_mod_mul(result->Z, tmp, H, p, ctx);

    // print results
    printf("point_add << X: %s\n", BN_bn2hex(result->X));
    printf("point_add << Y: %s\n", BN_bn2hex(result->Y));
    printf("point_add << Z: %s\n", BN_bn2hex(result->Z));

cleanup:
    BN_free(U1); BN_free(U2); BN_free(S1); BN_free(S2); BN_free(H);
    BN_free(r); BN_free(H_squared); BN_free(H_cubed); BN_free(U1_H_squared);
    BN_free(tmp); BN_free(p);
}

// Function to compare two EC_POINTs
int compare_points(EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx) {
    BIGNUM *ax = BN_new();
    BIGNUM *ay = BN_new();
    BIGNUM *bx = BN_new();
    BIGNUM *by = BN_new();    

    EC_POINT_get_affine_coordinates_GFp(group, a, ax, ay, ctx);
    EC_POINT_get_affine_coordinates_GFp(group, b, bx, by, ctx);

    // Print compared values
    // printf("\ncompare_points ax: %s\n", BN_bn2hex(ax));
    // printf("compare_points bx: %s\n", BN_bn2hex(bx));
    // printf("compare_points ay: %s\n", BN_bn2hex(ay));
    // printf("compare_points by: %s\n", BN_bn2hex(by));

    int result = (BN_cmp(ax, bx) == 0 && BN_cmp(ay, by) == 0);

    BN_free(ax);
    BN_free(ay);
    BN_free(bx);
    BN_free(by);

    return result;
}

// Function to read test cases from file
int readTestCases(const char *filename, TestCase *cases) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    int numCases = 0;

    while (fgets(line, sizeof(line), file) && numCases < MAX_TEST_CASES) {
        TestCase *tc = &cases[numCases];
        sscanf(line, "%64s %64s %64s %64s %64s %64s %64s %64s",
               tc->Px, tc->Py, tc->Qx, tc->Qy,
               tc->ExpectedAddX, tc->ExpectedAddY,
               tc->ExpectedDoubleX, tc->ExpectedDoubleY);
        numCases++;
    }

    fclose(file);
    return numCases;
}

int main() {
    TestCase *cases = (TestCase*)malloc(MAX_TEST_CASES * sizeof(TestCase));
    int numCases = readTestCases("point_add_cases_full.txt", cases);
    if (numCases < 0) {
        fprintf(stderr, "Failed to read test cases\n");
        return 1;
    }

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();

    for (int i = 0; i < numCases; i++) {
        TestCase *tc = &cases[i];

        EC_POINT *P = EC_POINT_new(group);
        EC_POINT *Q = EC_POINT_new(group);
        EC_POINT *resultAdd = EC_POINT_new(group);
        EC_POINT *resultDouble = EC_POINT_new(group);
        EC_POINT *expectedAdd = EC_POINT_new(group);
        EC_POINT *expectedDouble = EC_POINT_new(group);

        // Initialize points P and Q from hex strings
        init_point_from_hex(group, P, tc->Px, tc->Py, ctx);
        init_point_from_hex(group, Q, tc->Qx, tc->Qy, ctx);
        init_point_from_hex(group, expectedAdd, tc->ExpectedAddX, tc->ExpectedAddY, ctx);
        init_point_from_hex(group, expectedDouble, tc->ExpectedDoubleX, tc->ExpectedDoubleY, ctx);

        #ifdef use_openssl
            // Point addition
            EC_POINT_add(group, resultAdd, P, Q, ctx);
        #else
            // Perform point addition using Jacobian coordinates
            EC_POINT_JACOBIAN P_jacobian, Q_jacobian, result_jacobian;
            EC_POINT_Jacobian_new(&P_jacobian);
            EC_POINT_Jacobian_new(&Q_jacobian);
            EC_POINT_Jacobian_new(&result_jacobian);
            // Convert affine points to Jacobian coordinates
            affine_to_jacobian(group, P, &P_jacobian, ctx);
            affine_to_jacobian(group, Q, &Q_jacobian, ctx);
            // Perform Jacobian point addition
            jacobian_point_add(group, &result_jacobian, &P_jacobian, &Q_jacobian, ctx);
            // Convert the result back to affine coordinates
            jacobian_to_affine(group, &result_jacobian, resultAdd, ctx);
        #endif

        #ifdef use_openssl
            // Perform point doubling using built-in function for comparison
            EC_POINT_dbl(group, resultDouble, P, ctx);
        #else
            // TODO: Implement own jacobian_point_dbl function
        #endif

        // Print compared values
        printf("\nTest case %d:\n", i + 1);
        printf("ExpectedAddX: %s\n", tc->ExpectedAddX);
        // printf("ResultAddY: %s\n", BN_bn2hex(resultAdd->Y));
        printf("ExpectedAddY: %s\n", tc->ExpectedAddY);
        // printf("ResultDoubleX: %s\n", BN_bn2hex(resultDouble->X));
        printf("ExpectedDoubleX: %s\n", tc->ExpectedDoubleX);
        // printf("ResultDoubleY: %s\n", BN_bn2hex(resultDouble->Y));
        printf("ExpectedDoubleY: %s\n", tc->ExpectedDoubleY);
        
        // Compare results
        int additionCorrect = compare_points(group, resultAdd, expectedAdd, ctx);
        int doublingCorrect = compare_points(group, resultDouble, expectedDouble, ctx);

        printf("Test case %d: Addition %s, Doubling %s\n", i + 1,
               additionCorrect ? "PASS" : "FAIL",
               doublingCorrect ? "PASS" : "FAIL");

        // Clean up
        EC_POINT_free(P);
        EC_POINT_free(Q);
        EC_POINT_free(resultAdd);
        EC_POINT_free(resultDouble);
        EC_POINT_free(expectedAdd);
        EC_POINT_free(expectedDouble);
        #ifndef use_openssl
            EC_POINT_Jacobian_free(&P_jacobian);
            EC_POINT_Jacobian_free(&Q_jacobian);
            EC_POINT_Jacobian_free(&result_jacobian);
        #endif
    }

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    free(cases);

    return 0;
}