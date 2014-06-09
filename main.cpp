#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <unistd.h>
#include "sse.h"
#include <tmmintrin.h>
#include <xmmintrin.h>
#include <emmintrin.h>

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
    
    int p509[] = {509, 23, 3, 2, 0, -1};
    int p163[] = {163, 7, 6, 3, 0, -1};
    
    int _g[] = {350, 165, 8, 7, 6, 5, 3, 0, -1};
    BIGNUM * g = BN_new();
    BIGNUM * h = BN_new();
    BIGNUM * mod = BN_new();
    BIGNUM * r = BN_new();
    BIGNUM * r2 = BN_new();
//    
//    BN_GF2m_arr2poly(_g, g);
//    BN_GF2m_mod_shrop163_sse(r, g);
//    print_BN(r);
//    
//    BN_GF2m_mod_arr(r2, g, p163);
//    
//    print_BN(r2);
//    
//    return 0;
    
    
    
    int iter = 100000;
    
    BIGNUM ** Ru = new BIGNUM*[iter];
    //BN_rand(number, 2047, 1, 1);
    for(int i = 0; i < iter; i++)
    {
        Ru[i] = BN_new();
        BN_rand(Ru[i], 1024, 1, 1);
    }
    
    
    float t = clock();
    
    for(int i = 0; i< iter; i++)
    {
        //BN_GF2m_mod_shrop509(r, Ru[i]);
        //BN_GF2m_mod_shrop509_sse(r, Ru[i]);
        //BN_GF2m_mod_bin_original(r, Ru[i], p509);
        //BN_GF2m_mod_shrop173(r, Ru[i]);
        //BN_GF2m_mod_shrop163_sse(r, Ru[i]);
        BN_GF2m_mod_shrop173_sse(r, Ru[i]);
    }
    
    t = clock() - t;
    
    printf("time to original: %f \n", t);
    
//    float tt = clock();
//    
//    for(int i = 0; i< iter; i++)
//    {
//       BN_GF2m_mod_shrop509_sse(r2, Ru[i]);
//    }
//    
//    tt = clock() - tt;
    
//    printf("time to sse: %f \n", tt/CLOCKS_PER_SEC);
    
    
    float finalt = t/iter;
    
//    float finaltt = tt/iter;
    
    printf("final time original: %f \n", finalt);
//    printf("final time sse %f \n", finaltt/CLOCKS_PER_SEC);
    

}