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

    int _g[] = {1024, 12, 2, 1, 0, -1};
    int _p[] = {509, 23, 3, 2, 0, -1};
    //int _g[] = {76, 17, 13, 9, 7, 1, 0, -1};
    //int _h[] = {124, 16, 12, 8, 4, 1, 0, -1};
    
    
    BIGNUM * g = BN_new();
    BIGNUM * p = BN_new();
    //BIGNUM * mod = BN_new();
    BIGNUM * r = BN_new();
    BIGNUM * r2 = BN_new();
    
    BN_GF2m_arr2poly(_g, g);
    BN_GF2m_arr2poly(_p, p);
    
    BN_GF2m_mod(r, g, p);
    BN_GF2m_mod_shrop509_sse(r2, g);
    
    if(BN_cmp(r, r2) == 0)
    {
        printf("krababonga\n");
    }
    else
    {
        printf("fuck you!\n");
    }
    
    int _r[16] = {0};
    int _r2[16] = {0};
    
    BN_GF2m_poly2arr(r, _r, 16);
    BN_GF2m_poly2arr(r2, _r2, 16);
    
    print_pol(_r, 16);
    print_pol(_r2, 16);
}