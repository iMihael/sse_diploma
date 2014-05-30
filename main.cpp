#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <unistd.h>
#include "sse.h"

int myRand(int low, int high) {
   srand(time(NULL));
   return rand() % (high - low + 1) + low;
}


void gen_Nnom(BIGNUM * p,const int N, int max)
{
    //int _p[N + 1] = {0};
    int * _p = new int[N+1];
    _p[N] = -1;
    
    for(int i=0;i<N-1;i++)
    {
        _p[i] = myRand(max - 32, max);
        max -= 32;
    }
    
    BN_GF2m_arr2poly(_p, p);
}







int main()
{
    int p[] = {360, 350, 300, 298, 0, -1};
    //int _g[] = {76, 17, 13, 9, 7, 1, 0, -1};
    //int _h[] = {124, 16, 12, 8, 4, 1, 0, -1};
    
    
    
    
    BIGNUM * g = BN_new();
    BIGNUM * h = BN_new();
    BIGNUM * mod = BN_new();
    BIGNUM * r = BN_new();
    BIGNUM * r2 = BN_new();
    
    int iter = 0xFFFFF;
    
    BIGNUM ** Ru = new BIGNUM*[iter];
    //BN_rand(g, 2047, 1, 1);
    for(int i = 0; i < iter; i++)
    {
        Ru[i] = BN_new();
//        gen_5nom(Ru[i], 16000);
        //gen_Nnom(Ru[i], 5, 590);
        BN_rand(Ru[i], 620, 1, 1);
    }
    
    
    float t = clock();
    
    for(int i = 0; i< iter; i++)
    {
        BN_GF2m_mod_bin_original(r, Ru[i], p);
    }
    
    t = clock() - t;
    
    printf("time to original: %f \n", t/CLOCKS_PER_SEC);
    
    float tt = clock();
    
    for(int i = 0; i< iter; i++)
    {
       BN_GF2m_mod_bin_sse(r2, Ru[i], p);
    }
    
    tt = clock() - tt;
    
    printf("time to sse: %f \n", tt/CLOCKS_PER_SEC);
    
    
    float finalt = t/iter;
    float finaltt = tt/iter;
    
    printf("final time original: %f \n", finalt/CLOCKS_PER_SEC);
    printf("final time sse %f \n", finaltt/CLOCKS_PER_SEC);
    
    if(BN_cmp(r, r2)!=0)
    {
        printf("fail");
    }
    
    //BN_GF2m_arr2poly(_g, g);
    //BN_GF2m_arr2poly(_h, h);
    //BN_GF2m_mod_mul_arr(r, g, h, p, BN_CTX_new());
    //int ret[32] = {0};
    //BN_GF2m_poly2arr(r, ret, 32);
    //print_pol(ret, 32);
    //int ret2[32] = {0};
    //BN_GF2m_mod_mul_comb(r2, g, h, p);
    //BN_GF2m_poly2arr(r2, ret2, 32);
    //print_pol(ret2, 32);
}