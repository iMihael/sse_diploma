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
    
//    for(int i=1; i < d; i++ )
//    {
//        h1 = h1 << 1;
//        h1 = binary_reduction2(m,k3,k2,k1,h1);
//        if(g & (1 << i))
//            s ^= h1;
//    }
    
    
    return s;
}


int main()
{
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
    
    
    int gg[]= {4, 2,  0, -1};
    int hh[] = {2, 1, 0, -1};
    int ff[] = {6, 4, 3, 1, 0, -1};
    int ss[16] = {0};
    BN_GF2m_arr2poly(gg, _g);
    BN_GF2m_arr2poly(hh, _h);
    BN_GF2m_arr2poly(ff, _f);
    
    BN_GF2m_mod_mul(_s, _g, _h, _f, gfg);
    
    BN_GF2m_poly2arr(_s, ss, 16);
    
    
    for(int i = 0; i < 16; i++)
    {
        printf("%d|", ss[i]);
    }
    
    
    
}