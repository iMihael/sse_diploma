#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <unistd.h>
#include "sse.h"

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
    
    int gg[]= {15635, 999, 500,45, 5, 0, -1};
    int hh[] = {635, 600, 3, 0, -1};
    int ff[] = {8000, 56, 47, 1, 0, -1};
    int ss[64] = {0};
    
    BN_GF2m_arr2poly(gg, _g);
    BN_GF2m_arr2poly(hh, _h);
    BN_GF2m_arr2poly(ff, _f);
    
    float t=clock();
    
    for (int i = 0; i<0xFFF; i++)
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
    for (int i = 0; i < 0xFFF; i++)
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