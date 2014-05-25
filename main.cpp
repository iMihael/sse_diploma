#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <unistd.h>

#include "sse.h"

int binary_mul(int g, int h, int mod)
{
    int d = 4;
    int m = 6;
    int k3 = 4;
    int k2 = 3;
    int k1 = 1;
    
    int s = 0;
    if(g & 1)
        s = h;
    
    for(int i=1; i <= d; i++)
    {
        if(g & (1 << i))
        {
            s ^= h << i;
            s = binary_reduction2(m, k3, k2, k1, s);
        }
    }
    
    return s;
}

void BN_GF2m_mod_mul_bin_sse(BIGNUM *r, BIGNUM *g, BIGNUM *h, const int p[])
{
    // m = p[0]
    // k3 = p[1]
    // k2 = p[2]
    // k1 = p[3]
    
    int arr[16] = {};
    BN_GF2m_poly2arr(g, arr, 16);
    int d = arr[0];
    
    BIGNUM * s = BN_new();
    if( BN_is_bit_set(g, 0) )
        BN_copy(s, h);
    
    for(int i=1; i<=d;i++)
    {
        if(BN_is_bit_set(g, i))
        {
            BIGNUM * h1 = BN_new();
            BN_lshift(h1, h, i);
            BN_GF2m_add_sse(s, s, h1);
            BN_GF2m_mod_bin_sse(s, s, p);
        }
    }
    
    BN_copy(r, s);
}


void BN_GF2m_mod_mul_bin_original(BIGNUM *r, BIGNUM *g, BIGNUM *h, const int p[])
{
    // m = p[0]
    // k3 = p[1]
    // k2 = p[2]
    // k1 = p[3]
    
    int arr[16] = {};
    BN_GF2m_poly2arr(g, arr, 16);
    int d = arr[0];
    
    BIGNUM * s = BN_new();
    if( BN_is_bit_set(g, 0) )
        BN_copy(s, h);
    
    for(int i=1; i<=d;i++)
    {
        if(BN_is_bit_set(g, i))
        {
            BIGNUM * h1 = BN_new();
            BN_lshift(h1, h, i);
            BN_GF2m_add_original(s, s, h1);
            BN_GF2m_mod_bin_original(s, s, p);
        }
    }
    
    BN_copy(r, s);
}


int main()
{
    int __ff[] = {10, 5, 4, 1, 0, -1};
    BIGNUM * test = BN_new();
    BIGNUM * result = BN_new();
    BN_set_word(test, 5259);
    
    BN_GF2m_mod_bin_original(result, test, __ff);
    BN_GF2m_mod_arr(result, test, __ff);
    

    
    // f = x6 + x4 + x3 + x + 1 // mod
    // g = x4 + x2 + 1
    // h = x2 + x + 1
    
    int mod = 0x5B;
    int g = 0x15;
    int h = 0x7;

    
    int r = binary_mul(g, h, mod);
    
    printf("%x\n", r);
    
    BIGNUM *_g = BN_new();
    BIGNUM *_h = BN_new();
    BIGNUM *_f = BN_new();
    BIGNUM *_s = BN_new();
    BN_CTX *gfg = BN_CTX_new();
    
    int gg[]= {999, 45, 5, 0, -1};
    int hh[] = {635, 3, 0, -1};
    int ff[] = {560, 56, 47, 1, 0, -1};
    int ss[64] = {0};
    
    BN_GF2m_arr2poly(gg, _g);
    BN_GF2m_arr2poly(hh, _h);
    BN_GF2m_arr2poly(ff, _f);
    
    float t=clock();
    
    for (int i = 0; i<0xFFFF; i++)
    {
        BN_GF2m_mod_mul_bin_original(_s, _g, _h, ff);
    }
    
    t = clock() - t;
    
    printf("%f\n", t);
   
    BN_GF2m_poly2arr(_s, ss, 64);
    
    printf("\n");
    
    for(int i = 0; i < 64; i++)
    {
        printf("%d|", ss[i]);
    }
    
    printf("\n");
    
    BIGNUM *_g2 = BN_new();
    BIGNUM *_h2 = BN_new();
    BIGNUM *_f2 = BN_new();
    BIGNUM *_s2 = BN_new();
       
    int ss2[64] = {0};
    
    BN_GF2m_arr2poly(gg, _g2);
    BN_GF2m_arr2poly(hh, _h2);
    BN_GF2m_arr2poly(ff, _f2);
    
    t = clock();
    for (int i = 0; i < 0xFFFF; i++)
    {
        BN_GF2m_mod_mul_bin_sse(_s2, _g2, _h2, ff);
    }
    t = clock() - t;
    
    printf("%f", t);
    
    BN_GF2m_poly2arr(_s2, ss2, 64);
    
    printf("\n");
    
    for(int i = 0; i < 64; i++)
    {
        printf("%d|", ss2[i]);
    }
    
    
   
    
}