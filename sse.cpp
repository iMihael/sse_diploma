#include <openssl/bn.h>
#include <openssl/err.h>
#include <tmmintrin.h>
#include <xmmintrin.h>
#include <emmintrin.h>

int BN_set_bit_value(BIGNUM *a, int n, BN_ULONG bit)
{
    int i,j,k;

    if (n < 0)
            return 0;

    i=n/BN_BITS2;
    j=n%BN_BITS2;
    if (a->top <= i)
            {
            if (bn_wexpand(a,i+1) == NULL) return(0);
            for(k=a->top; k<i+1; k++)
                    a->d[k]=0;
            a->top=i+1;
            }

    //x = x & ~(1 << n) | (b << n);
    a->d[i] = a->d[i] & ~(((BN_ULONG)1)<<j) | (bit << j);
    //a->d[i]|=(((BN_ULONG)1)<<j);
    bn_check_top(a);
    return(1);
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

    
    for (i = 0; i < bt->top / 4; i++)
    {
 //       __m128i * at128 = (__m128i *)at->d;
//        __m128i _at128 = *at128;
//        __m128i * bt128 = (__m128i *)bt->d;
//        __m128i _bt128 = *bt128;
        
//        __m128 __at128 = _mm_load_ps(((const float *)at->d) + i * 4);
//        __m128 __bt128 = _mm_load_ps(((const float *)bt->d) + i * 4);
//        __m128 at_xor_bt = _mm_xor_ps(__at128, __bt128);
////        _mm_store_ps(((float *)r->d) + i*4, at_xor_bt);
//        *((__m128 *)r->d + i) = at_xor_bt;
        
        _mm_store_ps(((float *)r->d) + i*4, _mm_xor_ps(
                _mm_load_ps(((const float *)at->d) + i * 4),
                _mm_load_ps(((const float *)bt->d) + i * 4))
                );
        //_mm_xor_ps()
        
      // *((__m128i *)r->d + i) = _mm_xor_si128(*(((__m128i *)at->d) + i), *(((__m128i *)bt->d) + i) );
    }

    for (i = (bt->top / 4) * 4; i < bt->top; i++)
    {
        r->d[i] = at->d[i] ^ bt->d[i];
    }
    
    for (; i < at->top; i++)
    {
        r->d[i] = at->d[i];
    }

    r->top = at->top;
    bn_correct_top(r);

    return 1;
}



/* Performs modular reduction of a and store result in r.  r could be a. */
int BN_GF2m_mod_arr_sse(BIGNUM *r, const BIGNUM *a, const int p[])
{
    int j, k;
    int n, dN, d0, d1;
    BN_ULONG zz, *z;

    bn_check_top(a);

    if (!p[0])
    {
        /* reduction mod 1 => return 0 */
        BN_zero(r);
        return 1;
    }

    /* Since the algorithm does reduction in the r value, if a != r, copy
     * the contents of a into r so we can do reduction in r. 
     */
    if (a != r)
    {
        if (!bn_wexpand(r, a->top)) return 0;
        for (j = 0; j < a->top; j++)
        {
                r->d[j] = a->d[j];
        }
        r->top = a->top;
    }
    z = r->d;

    /* start reduction */
    dN = p[0] / BN_BITS2;  
    for (j = r->top - 1; j > dN;)
    {
        zz = z[j];
        if (z[j] == 0) { j--; continue; }
        z[j] = 0;

        for (k = 1; p[k] != 0; k++)
        {
            /* reducing component t^p[k] */
            n = p[0] - p[k];
            d0 = n % BN_BITS2;  d1 = BN_BITS2 - d0;
            n /= BN_BITS2; 
            z[j-n] ^= (zz>>d0);
            if (d0) z[j-n-1] ^= (zz<<d1);
        }

        /* reducing component t^0 */
        n = dN;  
        d0 = p[0] % BN_BITS2;
        d1 = BN_BITS2 - d0;
        z[j-n] ^= (zz >> d0);
        if (d0) z[j-n-1] ^= (zz << d1);
    }

    /* final round of reduction */
    while (j == dN)
    {
        d0 = p[0] % BN_BITS2;
        zz = z[dN] >> d0;
        if (zz == 0) break;
        d1 = BN_BITS2 - d0;

        /* clear up the top d1 bits */
        if (d0)
                z[dN] = (z[dN] << d1) >> d1;
        else
                z[dN] = 0;
        z[0] ^= zz; /* reduction t^0 component */

        for (k = 1; p[k] != 0; k++)
        {
            BN_ULONG tmp_ulong;

            /* reducing component t^p[k]*/
            n = p[k] / BN_BITS2;   
            d0 = p[k] % BN_BITS2;
            d1 = BN_BITS2 - d0;
            z[n] ^= (zz << d0);
            tmp_ulong = zz >> d1;
            
            if (d0 && tmp_ulong)
                z[n+1] ^= tmp_ulong;
        }
    }

    bn_correct_top(r);
    return 1;
}

/* Performs modular reduction of a by p and store result in r.  r could be a.
 *
 * This function calls down to the BN_GF2m_mod_arr implementation; this wrapper
 * function is only provided for convenience; for best performance, use the 
 * BN_GF2m_mod_arr function.
 */
int BN_GF2m_mod_sse(BIGNUM *r, const BIGNUM *a, const BIGNUM *p)
{
    int ret = 0;
    int arr[6];
    bn_check_top(a);
    bn_check_top(p);
    ret = BN_GF2m_poly2arr(p, arr, sizeof(arr)/sizeof(arr[0]));
    if (!ret || ret > (int)(sizeof(arr)/sizeof(arr[0])))
    {
        BNerr(BN_F_BN_GF2M_MOD,BN_R_INVALID_LENGTH);
        return 0;
    }
    ret = BN_GF2m_mod_arr_sse(r, a, arr);
    bn_check_top(r);
    return ret;
}
