#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <unistd.h>
#include "sse.h"


void BN_GF2m_mod_mul_comb(BIGNUM *r, BIGNUM *g, BIGNUM *h, const int mod[])
{
    //int d = BN_num_bits(g);
    int v = 32;
    int w = 4;
    //int p = d / v + 1;
    int p = g->top;
    int q = v / w;
    unsigned int u = 0;
    unsigned int mask = 0xF;
    
    int k = ((1 << w)/* - 1*/);
    BIGNUM ** Ru = new BIGNUM*[k];
    for(int i=0;i<k;i++)
    {
        Ru[i] = BN_new();
        //BN_zero(Ru[i]);
    }
    
    BIGNUM * Ut = BN_new();
    
    for(int i = 0; i < k; i++)
    {
        BN_set_word(Ut, i);
        BN_GF2m_mod_mul_bin_original(Ru[i], Ut, h, mod);
        //BN_GF2m_mod_mul_arr(Ru[i], Ut, h, mod, BN_CTX_new());
    }
    
    BIGNUM * S = BN_new();
    
    for(int ka = q - 1; ka >= 0; ka--)
    {
        for(int i=0;i<p;i++)
        {
            u = (g->d[i] & (mask << (ka * 4))) >> (ka * 4);
            
            
            for(int l=i, j=0;j<Ru[u]->top; l++, j++)
            {
                bn_wexpand(S, l + 1);
                S->d[l] ^= Ru[u]->d[j];
                S->top = l + 1;
            }
        }
        
        if(ka!=0)
        {
            BN_lshift(S, S, w);
            //BN_GF2m_mod_bin_original(S, S, mod);
            BN_GF2m_mod_arr(S, S, mod);
        }
    }
    
    //BN_GF2m_mod_bin_original(S, S, mod);
    BN_GF2m_mod_arr(S, S, mod);
    BN_copy(r, S);
}


void BN_GF2m_mod_mul_comb_sse(BIGNUM *r, BIGNUM *g, BIGNUM *h, const int mod[])
{
    int d = BN_num_bits(g);
    int v = 32;
    int w = 4;
    int p = d / v + 1;
    int q = v / w;
    unsigned int u = 0;
    unsigned int mask = 0xF;
    
    int k = ((1 << w)/* - 1*/);
    BIGNUM ** Ru = new BIGNUM*[k];
    for(int i=0;i<k;i++)
    {
        Ru[i] = BN_new();
        BN_zero(Ru[i]);
    }
    
    BIGNUM * Ut = BN_new();
    BN_set_word(Ut, 0);
    
    for(int i = 0; i < k; i++)
    {
        BN_set_word(Ut, i);
        BN_GF2m_mod_mul_bin_sse(Ru[i], Ut, h, mod);
    }
    
    BIGNUM * S = BN_new();
    
    for(int ka = q - 1; ka >= 0; ka--)
    {
        for(int i=0;i<p;i++)
        {
            u = (g->d[i] & (mask << (ka * 4))) >> (ka * 4);
            
            for(int l=i, j=0;j<Ru[u]->top; l++, j++)
            {
                bn_wexpand(S, i+1);
                S->d[l] ^= Ru[u]->d[j];
                S->top = i + 1;
            }
        }
        
        if(ka!=0)
        {
            BN_lshift(S, S, w);
            BN_GF2m_mod_bin_sse(S, S, mod);
        }
    }
    
    BN_GF2m_mod_bin_sse(S, S, mod);
    BN_copy(r, S);
}

void print_pol(const int p[], int n)
{
    for(int i=0;i<n;i++)
    {
        printf("%d|", p[i]);
    }
    printf("\n");
}

int main()
{
    int p[] = {31, 13, 9, 7, 0, -1};
    int _g[] = {24, 17, 13, 9, 7, 1, 0, -1};
    int _h[] = {20, 16, 12, 8, 4, 1, 0, -1};
    
    
    BIGNUM * g = BN_new();
    BIGNUM * h = BN_new();
    BIGNUM * mod = BN_new();
    BIGNUM * r = BN_new();
    
    
    BN_GF2m_arr2poly(_g, g);
    BN_GF2m_arr2poly(_h, h);

    BN_GF2m_mod_mul_comb(r, g, h, p);
    
    int ret[64] = {0};
    BN_GF2m_poly2arr(r, ret, 64);
    print_pol(ret, 64);
    
    BN_GF2m_mod_mul_bin_original(r, g, h, p);

    BN_GF2m_poly2arr(r, ret, 64);
    print_pol(ret, 64);
    
    BN_GF2m_mod_mul_arr(r, g, h, p, BN_CTX_new());
    BN_GF2m_poly2arr(r, ret, 64);
    print_pol(ret, 64);
    
    
 
}