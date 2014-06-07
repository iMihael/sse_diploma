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
    int p[] = {1024, 12, 2, 1, 0, -1};
    //int _g[] = {76, 17, 13, 9, 7, 1, 0, -1};
    //int _h[] = {124, 16, 12, 8, 4, 1, 0, -1};
    
    
    
    
    BIGNUM * g = BN_new();
    BIGNUM * h = BN_new();
    BIGNUM * mod = BN_new();
    BIGNUM * r = BN_new();
    BIGNUM * r2 = BN_new();
    
    int iter = 0x100000;
    
    BIGNUM ** Hu = new BIGNUM*[iter];
    BIGNUM ** Gu = new BIGNUM*[iter];
    //BN_rand(g, 2047, 1, 1);
    for(int i = 0; i < iter; i++)
    {
        Gu[i] = BN_new();
//        gen_5nom(Ru[i], 16000);
        gen_Nnom(Gu[i], 5, 1023);
        //BN_rand(Ru[i], 4000, 1, 1);
    }
    
    for(int i = 0; i < iter; i++)
    {
        Hu[i] = BN_new();
//        gen_5nom(Ru[i], 16000);
        gen_Nnom(Hu[i], 5, 1023);
        //BN_rand(Ru[i], 4000, 1, 1);
    }
    
    float t = clock();
    
    for(int i = 0; i< iter; i++)
    {
        BN_GF2m_mod_mul_comb(r, Gu[i], Hu[i], p);
    }
    
    t = clock() - t;
    
    printf("time to original: %f \n", t/CLOCKS_PER_SEC);
    
    
    
    float tt = clock();
    for(int i = 0; i< iter; i++)
    {
       BN_GF2m_mod_mul_comb_sse(r2, Gu[i], Hu[i], p);
    }
    tt = clock() - tt;
    printf("time to sse: %f \n", tt/CLOCKS_PER_SEC);
    
    
    float finalt = t/iter;
    float finaltt = tt/iter;
    
    printf("final time original: %f \n", finalt/CLOCKS_PER_SEC);
    printf("final time sse %f \n", finaltt/CLOCKS_PER_SEC);
    
    if(BN_cmp(r, r2) != 0)
    {
        printf("FAIL!\n");
    }
    
}