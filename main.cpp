#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <unistd.h>
#include "sse.h"











int main()
{
    int p[] = {129, 23, 3, 2, 0, -1};
    int _g[] = {63, 17, 13, 9, 7, 1, 0, -1};
    int _h[] = {45, 16, 12, 8, 4, 1, 0, -1};
    
    
    BIGNUM * g = BN_new();
    BIGNUM * h = BN_new();
    BIGNUM * mod = BN_new();
    BIGNUM * r = BN_new();
    BIGNUM * r2 = BN_new();
    
    BN_GF2m_arr2poly(_g, g);
    BN_GF2m_arr2poly(_h, h);
    
    BN_GF2m_mod_mul_arr(r, g, h, p, BN_CTX_new());
    
    int ret[32] = {0};
    BN_GF2m_poly2arr(r, ret, 32);
    print_pol(ret, 32);
    
    int ret2[32] = {0};
    BN_GF2m_mod_mul_comb(r2, g, h, p);
    BN_GF2m_poly2arr(r2, ret2, 32);
    print_pol(ret2, 32);
}