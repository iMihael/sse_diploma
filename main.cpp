#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <unistd.h>

#include "sse.h"


int xor_bit(int g, int pos1, int pos2)
{
    return g & ~(1 << pos1) | ((((g & (1 << pos1)) >> pos1) ^ ((g & (1 << pos2)) >> pos2)) << pos1);
}

int set_bit(int t, int pos, int val)
{
    return t & ~(1 << pos) | (val << pos);
}

void BN_GF2m_mod_bin(BIGNUM *r, BIGNUM *a, const int p[])
{
    // m = p[0]
    // k3 = p[1]
    // k2 = p[2]
    // k1 = p[3]
    
    int gi = 0;
    
    for(int i = 2 * p[0] - 1; i >= p[0]; i--)
    {
        gi = BN_is_bit_set(a, i);
        BIGNUM * _t = BN_new();
        BN_set_bit_value(_t, i - p[0], gi);
        BN_set_bit_value(_t, i - p[0]+p[1], gi);
        BN_set_bit_value(_t, i - p[0]+p[2], gi);
        BN_set_bit_value(_t, i - p[0]+p[3], gi);
        
        BN_GF2m_add_sse(a, a, _t);
    }
    
    
    
    BN_copy(r, a);
    BN_mask_bits(r, p[0]);
}

int main()
{
    int m = 13;
    int modulo_mask = 0;
    
    for(int i=0;i<m;i++)
    {
        modulo_mask |= 1 << i;
    }
    
    int k3 = 9;
    int k2 = 6;
    int k1 = 2;
    
    // mod = x6 + x4 + x3 + x + 1
    //int mod = 0x5B;
    
    //g = x7 + x4 + x2 + 1
    int g;
    
    int iteration = 0xFFFF;
    float t = clock();
    
    
    for(int j = 0;j<iteration;j++)
    {
        g = 0x82B01;
        for(int i = 2 * m -1; i >= m; i--)
        {
            g = xor_bit(g, i-m, i);
            g = xor_bit(g, i - m + k3, i);
            g = xor_bit(g, i - m + k2, i);
            g = xor_bit(g, i - m + k1, i);
        }
    }
    
    t = clock() - t;
    printf("%f\n", t);
    
    g &= modulo_mask;
    printf("%x\n", g);
    
    
    
    
    
    t = clock();
    
    for(int j = 0;j<iteration;j++)
    {
        g = 0x82B01;
        //int _t = 0;
        int gi = 0;
        
        for(int i = 2 * m -1; i >= m; i--)
        {
            gi = (g & (1 << i)) >> i;
            int _t = set_bit(0, i-m, gi);
            _t = set_bit(_t, i-m+k3, gi);
            _t = set_bit(_t, i-m+k2, gi);
            _t = set_bit(_t, i-m+k1, gi);
            g = g ^ _t;
        }
    }
    
    t = clock() - t;
    printf("%f\n", t);
    
    g &= modulo_mask;
    printf("%x\n", g);
    
    
    
    
    
    
    
    
    
    BIGNUM * modb = BN_new();
    int mod_arr[] = {13, 9, 6, 2, 0, -1};
    BN_GF2m_arr2poly(mod_arr, modb);
    
    BIGNUM * gb = BN_new();
    int g_arr[] = {19, 13, 11, 9, 8, 0, -1};
    BN_GF2m_arr2poly(g_arr, gb);
    
    BIGNUM * rb = BN_new();
    
    BN_GF2m_mod_bin(rb, gb, mod_arr);
    
    //classic BIGNUM GF2m_mod example
    
    //BN_GF2m_mod(rb, gb, modb);
    int r_arr[16] = {0};
    BN_GF2m_poly2arr(rb, r_arr, 16);
    
    for(int i=0;i<16;i++)
        printf("%d|", r_arr[i]);
    
    
}