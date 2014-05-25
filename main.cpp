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
    
    int iteration = 0xFFFFFF;
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
    
    BN_GF2m_mod(rb, gb, modb);
    int r_arr[16] = {0};
    BN_GF2m_poly2arr(rb, r_arr, 16);
    
    for(int i=0;i<16;i++)
        printf("%d|", r_arr[i]);
    
    // r = 0x37
    // r = x5 + x4 + x2 + x + 1
    
//    BIGNUM * a = BN_new();
//    BIGNUM * r = BN_new();
//    BIGNUM * r2 = BN_new();
//    BIGNUM * p = BN_new();
//    int n = 0xFFFFF;
//    
//    BN_rand(a, 65384, 1, 1);
//    BN_rand(p, 64384, 1, 1);
    
    
    
    
//    int _aarray[] = {176 ,15, 1, 0, -1};
//    int _barray[] = {163 , 7, 1, 0, -1};
//    
//    BN_GF2m_arr2poly(_aarray, a);
//    BN_GF2m_arr2poly(_barray, p);
    
    
//    float t;
//
//    t = clock();
//    for(int j=0;j<n;j++)
//        BN_GF2m_add_sse(r, a, p);
//    
//    t = clock() - t; // время выполнения
//
//    float t1;
//
//    t1 = clock();
//    for(int j=0;j<n;j++)
//        BN_GF2m_add_original(r2, a, p);
//    t1 = clock() - t; // время выполнения
//
//    t /= n;
//    t1 /= n;
//
//    printf("sse -> %f\n",t); 
//    printf("openssl -> %f",t1);
//    
//    if(BN_cmp(r, r2))
//    {
//        printf("\nresults is equal\n");
//    }
    
    //BN_rs
    
//    BN_GF2m_mod()
    
//    int l = sizeof(BN_ULONG);
//    l = sizeof(unsigned long long);
//    
//    BIGNUM * a = BN_new();
//    BIGNUM * p = BN_new();
//    BIGNUM * r = BN_new();
//    
//    int _p[] = {173, 10, 2, 1, 0, -1};
//    int _a[] = {191, 9, 0, -1};
//    
//    int resule[16] = {0};
//    
//    BN_GF2m_arr2poly(_p, p);
//    //BN_set_bit(p, 225);
//    //BN_print_fp(stdout, p);
//    
//    for(int i=0;i<p->dmax;i++)
//    {
//        printf("%lx|", p->d[i]);
//    }
//    return 1;
//    
//    BN_GF2m_arr2poly(_a, a);
//    
//    BN_GF2m_mod_original(r, a, p);
//    
//    BN_GF2m_poly2arr(r, resule, 16);
//    
//    for(int i=0;i<16;i++)
//    {
//        printf("%d|", resule[i]);
//    }
//    
//    BN_GF2m_mod_shrop(r, a);
//    
//    BN_GF2m_poly2arr(r, resule, 16);
//    
//    printf("\n");
//    for(int i=0;i<16;i++)
//    {
//        printf("%d|", resule[i]);
//    }

}