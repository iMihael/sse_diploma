#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/bn.h>
//#include <tmmintrin.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include "sse.h"

void BN_GF2m_mod_mul_comb_sse(BIGNUM *r, BIGNUM *g, BIGNUM *h, const int mod[])
{
    int v = 32;
    int w = 4;
    int p = g->top;
    int q = v / w;
    
    unsigned int u = 0;
    unsigned int mask = 0xF;
    
    int k = ((1 << w)/* - 1*/);
    BIGNUM ** Ru = new BIGNUM*[k];
    for(int i=0;i<k;i++)
    {
        Ru[i] = BN_new();
    }
    
    BIGNUM * Ut = BN_new();
    BN_zero(Ru[0]);
    BN_copy(Ru[1], h);
    
    
    for(int i = 2; i < k; i++)
    {
        BN_set_word(Ut, i);
        BN_GF2m_mod_mul_bin_sse(Ru[i], Ut, h, mod);
    }
    
    BIGNUM * S = BN_new();
    bn_wexpand(S, g->top * 2 + 1);
    
    
    for(int ka = q - 1; ka >= 0; ka--)
    {
        for(int i=0;i<p;i++)
        {
            u = (g->d[i] >> (ka * 4)) & mask;
            
            
            for(int l=i, j=0;j<Ru[k-1]->top; l++, j++)
            {
                S->d[l] ^= Ru[u]->d[j];
            }
        }
        
        BN_fx_top(S);
        if(ka!=0)
        {
            BN_lshift(S, S, w);
        }
    }
    

    BN_GF2m_mod_bin_sse(S, S, mod);
    BN_copy(r, S);
    
    BN_free(S);
    BN_free(Ut);
    for(int i=0;i<k;i++)
        BN_free(Ru[i]);
    
    delete [] Ru;
}

int BN_GF2m_add_sse(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int i;
    const BIGNUM *at, *bt;

    bn_check_top(a);
    bn_check_top(b);

    if (a->top < b->top) { at = b; bt = a; }
    else { at = a; bt = b; }

    if(bn_wexpand(r, at->top) == NULL)
            return 0;

    // maybe div 2 or div 3 or div 4
    for (i = 0; i < bt->top / 2; i++)
    {

        _mm_store_ps(((float *)r->d) + i*4, _mm_xor_ps(
                _mm_load_ps(((const float *)at->d) + i * 4),
                _mm_load_ps(((const float *)bt->d) + i * 4))
                );

        
       //*((__m128i *)r->d + i) = _mm_xor_si128(*(((__m128i *)at->d) + i), *(((__m128i *)bt->d) + i) );
    }

    for (i = (bt->top / 2) * 2; i < bt->top; i++)
    {
        r->d[i] = at->d[i] ^ bt->d[i];
    }
    
    for (; i < at->top; i++)
    {
        r->d[i] = at->d[i];
    }

    r->top = at->top;
    bn_correct_top(r);
//    BN_free((BIGNUM *)at);
//    BN_free((BIGNUM *)bt);
    return 1;
}

void BN_GF2m_mod_bin_sse(BIGNUM *r, BIGNUM *a, const int p[])
{
    // m = p[0]
    // k3 = p[1]
    // k2 = p[2]
    // k1 = p[3]
    
    int gi = 0;
    BN_copy(r, a);
    
    for(int i = 2 * p[0] - 1; i >= p[0]; i--)
    {
        gi = BN_is_bit_set(a, i);
        if(gi)
        {
            BIGNUM * _t = BN_new();
            BN_set_bit_value(_t, i - p[0], gi);
            BN_set_bit_value(_t, i - p[0]+p[1], gi);
            BN_set_bit_value(_t, i - p[0]+p[2], gi);
            BN_set_bit_value(_t, i - p[0]+p[3], gi);

            BN_GF2m_add_sse(r, r, _t);
            
            BN_free(_t);
        }
    }
    
    BN_mask_bits(r, p[0]);
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
            BN_free(h1);
        }
    }
    
    BN_copy(r, s);
    BN_free(s);
}