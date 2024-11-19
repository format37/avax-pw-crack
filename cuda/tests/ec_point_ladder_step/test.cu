#include <cuda_runtime.h>
#include <stdio.h>
#include "bignum.h"
#include "montgomery.h"
#include "point.h"

__device__ void init_test_vectors(
    EC_GROUP_CUDA *group,         // Curve parameters
    EC_POINT_JACOBIAN *base_point,    // P in affine coordinates
    EC_POINT_JACOBIAN *r_point,       // R in projective coordinates 
    EC_POINT_JACOBIAN *s_point        // S in projective coordinates
) {
    // Initialize group parameters
    // Group: secp256k1
    // Field: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    
    // Field prime
    init_zero(&group->field);
    group->field.d[3] = 0xFFFFFFFFFFFFFFFF;
    group->field.d[2] = 0xFFFFFFFFFFFFFFFF;
    group->field.d[1] = 0xFFFFFFFFFFFFFFFF;
    group->field.d[0] = 0xFFFFFFFEFFFFFC2F;
    group->field.top = 4;
    group->field.neg = false;

    // a = 0
    init_zero(&group->a);
    group->a.top = 1;
    group->a.neg = false;

    // b = 7
    init_zero(&group->b); 
    group->b.d[0] = 0x0700001AB7;
    group->b.top = 1;
    group->b.neg = false;

    // Initialize curve order
    init_zero(&group->order);
    group->order.d[3] = 0xFFFFFFFFFFFFFFFF;
    group->order.d[2] = 0xFFFFFFFFFFFFFFFE;
    group->order.d[1] = 0xBAAEDCE6AF48A03B;
    group->order.d[0] = 0xBFD25E8CD0364141;
    group->order.top = 4;
    group->order.neg = false;
    
    // Initialize base point P (secp256k1 generator point)
    // x coordinate
    init_zero(&base_point->X);
    base_point->X.d[3] = 0x9981E643E9089F48;
    base_point->X.d[2] = 0x979F48C033FD129C;
    base_point->X.d[1] = 0x231E295329BC66DB;
    base_point->X.d[0] = 0xD7362E5A487E2097;
    base_point->X.top = 4;
    base_point->X.neg = false;
    // y coordinate
    init_zero(&base_point->Y);
    base_point->Y.d[3] = 0xCF3F851FD4A582D6;
    base_point->Y.d[2] = 0x70B6B59AAC19C136;
    base_point->Y.d[1] = 0x8DFC5D5D1F1DC64D;
    base_point->Y.d[0] = 0xB15EA6D2D3DBABE2;
    base_point->Y.top = 4;
    base_point->Y.neg = false;
    // z coordinate
    init_zero(&base_point->Z);
    base_point->Z.d[0] = 0x01000003D1;
    base_point->Z.top = 1;
    base_point->Z.neg = false;

    // Set S point
    // x coordinate
    init_zero(&s_point->X);
    s_point->X.d[3] = 0x6905E1FC2278EFBB;
    s_point->X.d[2] = 0x2636020B60463145;
    s_point->X.d[1] = 0x289DDE613CBA2A22;
    s_point->X.d[0] = 0xB99C9635D9FDF005;
    s_point->X.top = 4;
    s_point->X.neg = false;
    // y coordinate
    init_zero(&s_point->Y);
    s_point->Y.d[3] = 0x30BA5EDD40D38D1F;
    s_point->Y.d[2] = 0x5B24C02BF347D852;
    s_point->Y.d[1] = 0xB7E5BD29A318FE73;
    s_point->Y.d[0] = 0x230398906311A839;
    s_point->Y.top = 4;
    s_point->Y.neg = false;
    // z coordinate
    init_zero(&s_point->Z);
    s_point->Z.d[3] = 0xDFA30ABA85E5DF8C;
    s_point->Z.d[2] = 0x7C231D3677E79480;
    s_point->Z.d[1] = 0x43812611FE566CF4;
    s_point->Z.d[0] = 0xF1FD34A59A26A44F;
    s_point->Z.top = 4;
    s_point->Z.neg = false;
    
    // Initialize R point
    // x coordinate
    init_zero(&r_point->X);
    r_point->X.d[3] = 0xA22EFED5BB4CEB00;
    r_point->X.d[2] = 0x243A15E5A0026879;
    r_point->X.d[1] = 0xDB96B2D2AD4BD252;
    r_point->X.d[0] = 0xBF22A6C2C5871863;
    r_point->X.top = 4;
    r_point->X.neg = false;

    // y coordinate
    init_zero(&r_point->Y);
    r_point->Y.d[3] = 0x946A5EDAF9E2D7E1;
    r_point->Y.d[2] = 0x2AD7EA0B5F5C1227;
    r_point->Y.d[1] = 0xAE990A3121368017;
    r_point->Y.d[0] = 0x13DA23E0DB979EF9;
    r_point->Y.top = 4;
    r_point->Y.neg = false;

    // z coordinate
    init_zero(&r_point->Z);
    r_point->Z.d[3] = 0xB7B83ADE508E1534;
    r_point->Z.d[2] = 0x7CB092DEBA1E3198;
    r_point->Z.d[1] = 0xF51B942FA0773EB7;
    r_point->Z.d[0] = 0xAFDFECF39D69ABF9;
    r_point->Z.top = 4;
    r_point->Z.neg = false;    
}

__device__ void init_test_vectors_x(
    EC_GROUP_CUDA *group,         // Curve parameters
    EC_POINT_JACOBIAN *base_point,    // P in affine coordinates
    EC_POINT_JACOBIAN *r_point,       // R in projective coordinates 
    EC_POINT_JACOBIAN *s_point        // S in projective coordinates
) {
    // Initialize group parameters
    // Group: secp256k1
    // Field: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    // A: 0
    // B: 0700001AB7
    // Order: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    // Field prime
    init_zero(&group->field);
    group->field.d[3] = 0xFFFFFFFFFFFFFFFF;
    group->field.d[2] = 0xFFFFFFFFFFFFFFFF;
    group->field.d[1] = 0xFFFFFFFFFFFFFFFF;
    group->field.d[0] = 0xFFFFFFFEFFFFFC2F;
    group->field.top = 4;
    group->field.neg = false;

    // a = 0
    init_zero(&group->a);
    group->a.top = 1;
    group->a.neg = false;

    // b = 7
    init_zero(&group->b); 
    group->b.d[0] = 0x0700001AB7;
    group->b.top = 1;
    group->b.neg = false;

    // Initialize curve order
    init_zero(&group->order);
    group->order.d[3] = 0xFFFFFFFFFFFFFFFF;
    group->order.d[2] = 0xFFFFFFFFFFFFFFFE;
    group->order.d[1] = 0xBAAEDCE6AF48A03B;
    group->order.d[0] = 0xBFD25E8CD0364141;
    group->order.top = 4;
    group->order.neg = false;
    
    // Initialize base point P (secp256k1 generator point)
    // [1] Initial point: p (generator): 0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    // X: 9981E643E9089F48979F48C033FD129C231E295329BC66DBD7362E5A487E2097
    // Y: CF3F851FD4A582D670B6B59AAC19C1368DFC5D5D1F1DC64DB15EA6D2D3DBABE2
    // Z: 01000003D1
    // Z_is_one: 1
    // EC_POINT_CUDA base_point;


    // bn_print_no_fuse("&base_point.X:", &base_point->X);
    // return;
    // x coordinate
    init_zero(&base_point->X);
    // // 9981E643E9089F48 979F48C033FD129C 231E295329BC66DB D7362E5A487E2097
    // base_point->X.d[3] = 0x9981E643E9089F48;
    // base_point->X.d[2] = 0x979F48C033FD129C;
    // base_point->X.d[1] = 0x231E295329BC66DB;
    // base_point->X.d[0] = 0xD7362E5A487E2097;
    // 9981E643E9089F48979F48C033FD129C231E295329BC66DBD7362E5A487E2097
    base_point->X.d[3] = 0x9981E643E9089F48;
    base_point->X.d[2] = 0x979F48C033FD129C;
    base_point->X.d[1] = 0x231E295329BC66DB;
    base_point->X.d[0] = 0xD7362E5A487E2097;
    base_point->X.top = 4;
    base_point->X.neg = false;

    // y coordinate
    init_zero(&base_point->Y);
    // // CF3F851FD4A582D6 70B6B59AAC19C136 8DFC5D5D1F1DC64D B15EA6D2D3DBABE2
    // base_point->Y.d[3] = 0xCF3F851FD4A582D6;
    // base_point->Y.d[2] = 0x70B6B59AAC19C136;
    // base_point->Y.d[1] = 0x8DFC5D5D1F1DC64D;
    // base_point->Y.d[0] = 0xB15EA6D2D3DBABE2;
    // CF3F851FD4A582D670B6B59AAC19C1368DFC5D5D1F1DC64DB15EA6D2D3DBABE2
    base_point->Y.d[3] = 0xCF3F851FD4A582D6;
    base_point->Y.d[2] = 0x70B6B59AAC19C136;
    base_point->Y.d[1] = 0x8DFC5D5D1F1DC64D;
    base_point->Y.d[0] = 0xB15EA6D2D3DBABE2;
    base_point->Y.top = 4;
    base_point->Y.neg = false;

    // z coordinate
    init_zero(&base_point->Z);
    // 00000001000003D1
    base_point->Z.d[0] = 0x00000001000003D1;
    base_point->Z.top = 1;
    base_point->Z.neg = false;

    // Copy S point from base_point
    // copy_jacobian_point(s_point, base_point);

    // Set S point accroding to values
    // x coordinate
    init_zero(&s_point->X);
    // 5D9C7BE194E8397AEA4C6964322235A3929D1128F00DFF18754526BC130E97B0
    s_point->X.d[3] = 0x5D9C7BE194E8397A;
    s_point->X.d[2] = 0xEA4C6964322235A3;
    s_point->X.d[1] = 0x929D1128F00DFF18;
    s_point->X.d[0] = 0x754526BC130E97B0;
    s_point->X.top = 4;
    s_point->X.neg = false;

    // y coordinate
    init_zero(&s_point->Y);
    // 9EB7840D46A6404D75DC64D82655BE6D1508B8C1F20C625E25C01D758F5A0271
    s_point->Y.d[3] = 0x9EB7840D46A6404D;
    s_point->Y.d[2] = 0x75DC64D82655BE6D;
    s_point->Y.d[1] = 0x1508B8C1F20C625E;
    s_point->Y.d[0] = 0x25C01D758F5A0271;
    s_point->Y.top = 4;
    s_point->Y.neg = false;

    // z coordinate
    init_zero(&s_point->Z);
    // E128853ACB0D914C79228AE1942C5D20E75E52284953EDE956FD766E7EB378DA
    s_point->Z.d[3] = 0xE128853ACB0D914C;
    s_point->Z.d[2] = 0x79228AE1942C5D20;
    s_point->Z.d[1] = 0xE75E52284953EDE9;
    s_point->Z.d[0] = 0x56FD766E7EB378DA;
    s_point->Z.top = 4;
    s_point->Z.neg = false;

    // Initialize R point
    // x coordinate
    init_zero(&r_point->X);
    // // 7C75DD9524177D59 3C03889B8DCD9B1C B05FB7D2A3DA7FE8 BA9F29B104E7DB13
    // r_point->X.d[3] = 0x7C75DD9524177D59;
    // r_point->X.d[2] = 0x3C03889B8DCD9B1C;
    // r_point->X.d[1] = 0xB05FB7D2A3DA7FE8;
    // r_point->X.d[0] = 0xBA9F29B104E7DB13;
    // 8972D7419759E11A C13A11538F557C3A 5760A16981ECFE3E BCBB84BC41A263E0
    r_point->X.d[3] = 0x8972D7419759E11A;
    r_point->X.d[2] = 0xC13A11538F557C3A;
    r_point->X.d[1] = 0x5760A16981ECFE3E;
    r_point->X.d[0] = 0xBCBB84BC41A263E0;
    r_point->X.top = 4;
    r_point->X.neg = false;

    // y coordinate
    init_zero(&r_point->Y);
    // // 55DEBB381F4AD034 CC27CB48A46449AA A87D43FDB563384B 1CD20838E6FDDC9F
    // r_point->Y.d[3] = 0x55DEBB381F4AD034;
    // r_point->Y.d[2] = 0xCC27CB48A46449AA;
    // r_point->Y.d[1] = 0xA87D43FDB563384B;
    // r_point->Y.d[0] = 0x1CD20838E6FDDC9F;
    // 946A5EDAF9E2D7E1 2AD7EA0B5F5C1227 AE990A3121368017 13DA23E0DB979EF9
    r_point->Y.d[3] = 0x946A5EDAF9E2D7E1;
    r_point->Y.d[2] = 0x2AD7EA0B5F5C1227;
    r_point->Y.d[1] = 0xAE990A3121368017;
    r_point->Y.d[0] = 0x13DA23E0DB979EF9;
    r_point->Y.top = 4;
    r_point->Y.neg = false;

    // z coordinate
    init_zero(&r_point->Z);
    // // 9E7F0A3FA94B05AC E16D6B355833826D 1BF8BABA3E3B8C9B 62BD4DA6A7B75B95
    // r_point->Z.d[3] = 0x9E7F0A3FA94B05AC;
    // r_point->Z.d[2] = 0xE16D6B355833826D;
    // r_point->Z.d[1] = 0x1BF8BABA3E3B8C9B;
    // r_point->Z.d[0] = 0x62BD4DA6A7B75B95;
    // 9028989D4A18DA0C0BD63FE04C06B8350379EF051DFFD3D649119832D1416931
    r_point->Z.d[3] = 0x9028989D4A18DA0C;
    r_point->Z.d[2] = 0x0BD63FE04C06B835;
    r_point->Z.d[1] = 0x0379EF051DFFD3D6;
    r_point->Z.d[0] = 0x49119832D1416931;
    r_point->Z.top = 4;
    r_point->Z.neg = false;    

    // Convert base point to Jacobian coordinates (s_point)
    // affine_to_jacobian(&base_point, s_point);

    // Compute r_point = 2P using point doubling in Jacobian coordinates
    // jacobian_point_double(r_point, s_point, &group->field, &group->a);
}

__device__ void print_point(const char* label, const EC_POINT_CUDA *point) {
    printf("%s:\n", label);
    bn_print_no_fuse("  x: ", &point->x);
    bn_print_no_fuse("  y: ", &point->y);
}

// In your main kernel function
__global__ void test_ladder_step() {
    printf("Starting ladder step test...\n");

    // Initialize group and points
    EC_GROUP_CUDA group;
    EC_POINT_JACOBIAN p_point, r_point, s_point;

    // Initialize test vectors
    init_test_vectors(&group, &p_point, &r_point, &s_point);

    printf("Test vectors initialized.\n");
    bn_print_no_fuse("Field prime: ", &group.field);
    bn_print_no_fuse("Base point a:", &group.a);
    bn_print_no_fuse("Base point b:", &group.b);
    bn_print_no_fuse("Curve order: ", &group.order);    
    print_jacobian_point("P point", &p_point);
    print_jacobian_point("R point", &r_point);
    print_jacobian_point("S point", &s_point);
    // return; // TODO: Remove this line

    // Perform ladder step
    int result = ec_point_ladder_step(&group, &r_point, &s_point, &p_point);

    if (result == 0) {
        printf("Ladder step operation failed!\n");
        return;
    }

    // Print results
    print_jacobian_point("Result R point", &r_point);
    print_jacobian_point("Result S point", &s_point);
    print_jacobian_point("Result P point", &p_point);
    printf("Ladder step test complete.\n");
}

int main() {
    // Set stack size
    size_t stackSize = 64 * 1024;  // 64KB
    cudaDeviceSetLimit(cudaLimitStackSize, stackSize);

    // Launch kernel
    test_ladder_step<<<1,1>>>();
    cudaDeviceSynchronize();

    // Check for errors
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) {
        printf("CUDA error: %s\n", cudaGetErrorString(error));
        return 1;
    }

    return 0;
}