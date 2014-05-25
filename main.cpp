#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <unistd.h>

#include "sse.h"




int main()
{
    int m = 13;
    
    
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
        g = binary_reduction1(m, k3, k2, k1, g);
    }
    
    t = clock() - t;
    printf("%f\n", t);
    
    
    printf("%x\n", g);
    
    
    
    
    
    t = clock();
    
    for(int j = 0;j<iteration;j++)
    {
        g = 0x82B01;
        g = binary_reduction2(m, k3, k2, k1, g);
    }
    
    t = clock() - t;
    printf("%f\n", t);
    
    
    printf("%x\n", g);
    
    BIGNUM * rb;
            
    t = clock();
        
    for(int j = 0;j<iteration;j++)
    {
        BIGNUM * modb = BN_new();
        int mod_arr[] = {321, 254, 180, 125, 0, -1};
        BN_GF2m_arr2poly(mod_arr, modb);

        BIGNUM * gb = BN_new();
        int g_arr[] = {413, 212, 192, 11, 9, 8, 0, -1};
        BN_GF2m_arr2poly(g_arr, gb);

        rb = BN_new();

        BN_GF2m_mod_bin_sse(rb, gb, mod_arr);
        
        //BN_GF2m_mod_bin_original(rb, gb, mod_arr);

        //classic BIGNUM GF2m_mod example

        //BN_GF2m_mod_original(rb, gb, modb);
    
    }
    
    t = clock() - t;
    printf("%f\n", t);
    
    int r_arr[16] = {0};
    BN_GF2m_poly2arr(rb, r_arr, 16);
    
    for(int i=0;i<16;i++)
        printf("%d|", r_arr[i]);
    
    
}