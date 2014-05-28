#include <openssl/bn.h>
#include <openssl/err.h>

#include "sse.h"

int BN_GF2m_add_original(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int i;
    const BIGNUM *at, *bt;

    bn_check_top(a);
    bn_check_top(b);

    if (a->top < b->top) { at = b; bt = a; }
    else { at = a; bt = b; }

    if(bn_wexpand(r, at->top) == NULL)
            return 0;

    for (i = 0; i < bt->top; i++)
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
/**
 * Works only on x86 (i386)
 * with modulo x163 + x7 + x6 + x3 + 1
 * @param r
 * @param a
  */
void BN_GF2m_mod_shrop163(BIGNUM *r, BIGNUM *a)
{
    BIGNUM * mod = BN_new();
    int p[] = {163, 7, 6, 3, 0, -1};
    BN_GF2m_arr2poly(p, mod);
    
    if(mod->top > a->top)
        BN_copy(r, a);
    
    int n = a->top;
    int L = mod->top;
    
    BN_ULONG T;
    
    for(int i = n; i>L; i--)
    {
        T = a->d[i];
        a->d[i - 6] ^= (T << 29);
        a->d[i - 5] ^= (T << 4) ^ (T << 3) ^ T ^ (T>>3);
        a->d[i - 4] ^= (T >> 28) ^ (T >> 29);
    }
    
    T = a->d[6] & 0xFFFFFFF8;
    a->d[1] ^= (T << 4) ^ (T << 3) ^ T ^ (T >> 3);
    a->d[2] ^= (T >> 28) ^ (T >> 29);
    a->d[6] &= 0x00000007;
    
    if(a->top > mod->top)
        a->top = mod->top;
    
    BN_copy(r, a);
}

/**
 * Works only on x86 (i386)
 * with modulo x509 + x23 + x3 + x2 + 1
 * @param r
 * @param a
  */
void BN_GF2m_mod_shrop509(BIGNUM *r, BIGNUM *a)
{
    //TODO: Fix!
    
    BIGNUM * mod = BN_new();
    int p[] = {509, 23, 3, 2, 0, -1};
    BN_GF2m_arr2poly(p, mod);
    
    if(mod->top > a->top)
        BN_copy(r, a);
    
    int n = a->top;
    int L = mod->top;
    
    BN_ULONG T;
    
    for(int i = n; i>L; i--)
    {
        T = a->d[i];
        a->d[i - 16] ^= (T<<3)^(T<<5)^(T<<6)^(T<<26);
        a->d[i - 17] ^= (T>>29)^(T>>27)^(T>>26)^(T>>6);
    }
    
    T = a->d[16] & 70000000;

    a->d[1] ^= (T>>29)^(T>>27)^(T>>26)^(T>>6);
    a->d[16] &= 0x8FFFFFFF;
    
    
    if(a->top > mod->top)
        a->top = mod->top;
    
    BN_copy(r, a);
}


/**
 * Works only on x86 (i386)
 * with modulo x503 + x3 + 1
 * @param r
 * @param a
  */
void BN_GF2m_mod_shrop503(BIGNUM *r, BIGNUM *a)
{
    BIGNUM * mod = BN_new();
    int p[] = {503, 3, 0, -1};
    BN_GF2m_arr2poly(p, mod);
    
    if(mod->top > a->top)
        BN_copy(r, a);
    
    int n = a->top;
    int L = mod->top;
    
    BN_ULONG T;
    
    for(int i = n; i>L; i--)
    {
        T = a->d[i];
        a->d[i - 16] ^= (T<<12)^(T<<9);
        a->d[i - 17] ^= (T>>20)^(T>>23);
    }
    
    T = a->d[16] & 0xFF800000;

    a->d[1] ^= (T>>20)^(T>>23);
    a->d[16] &= 0x007FFFFF;
    
    
    if(a->top > mod->top)
        a->top = mod->top;
    
    BN_copy(r, a);
}

/**
 * Works only on x86 (i386)
 * with modulo x173 + x10 + x2 + x + 1
 * @param r
 * @param a
  */
void BN_GF2m_mod_shrop173(BIGNUM *r, BIGNUM *a)
{
    BIGNUM * mod = BN_new();
    int p[] = {173, 10, 2, 1, 0, -1};
    BN_GF2m_arr2poly(p, mod);
    
    if(mod->top > a->top)
        BN_copy(r, a);
    
    int n = a->top;
    int L = mod->top;
    
    BN_ULONG T;
    
    for(int i = n; i>L; i--)
    {
        T = a->d[i];
        a->d[i - 5] ^= (T>>3)^(T>>11)^(T>>12)^(T>>13);
        a->d[i - 6] ^= (T<<29)^(T<<21)^(T<<20)^(T<<19);
    }
    
    T = a->d[6] & 0xFFFFE000;
    a->d[1] ^= (T>>3)^(T>>11)^(T>>12)^(T>>13);
    a->d[6] &= 0x1FFF;
    
    
    if(a->top > mod->top)
        a->top = mod->top;
    
    BN_copy(r, a);
}

/* Performs modular reduction of a and store result in r.  r could be a. */
int BN_GF2m_mod_arr_original(BIGNUM *r, const BIGNUM *a, const int p[])
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
int BN_GF2m_mod_original(BIGNUM *r, const BIGNUM *a, const BIGNUM *p)
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
    ret = BN_GF2m_mod_arr_original(r, a, arr);
    bn_check_top(r);
    return ret;
}





int xor_bit(int g, int pos1, int pos2)
{
    return g & ~(1 << pos1) | ((((g & (1 << pos1)) >> pos1) ^ ((g & (1 << pos2)) >> pos2)) << pos1);
}

int set_bit(int t, int pos, int val)
{
    return t & ~(1 << pos) | (val << pos);
}

/**
 * r = g mod m
 * 
 * m = x^m + x^k3 + x^k2 + x^k1 + 1
 * 
 * 
 * @param m
 * @param k3
 * @param k2
 * @param k1
 * @param g
 * @return 
 */
int binary_reduction1(int m, int k3, int k2, int k1, int g)
{
    int modulo_mask = 0;
    
    for(int i=0;i<m;i++)
    {
        modulo_mask |= 1 << i;
    }
    
    for(int i = 2 * m -1; i >= m; i--)
    {
        g = xor_bit(g, i-m, i);
        g = xor_bit(g, i - m + k3, i);
        g = xor_bit(g, i - m + k2, i);
        g = xor_bit(g, i - m + k1, i);
    }
    
    g &= modulo_mask;
    
    return g;
}

int binary_reduction2(int m, int k3, int k2, int k1, int g)
{
    int modulo_mask = 0;
    
    for(int i=0;i<m;i++)
    {
        modulo_mask |= 1 << i;
    }
    
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
    
    g &= modulo_mask;
    
    return g;
}

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
    
    return s;
}

void BN_GF2m_mod_mul_bin_original(BIGNUM *r, BIGNUM *g, BIGNUM *h, const int p[])
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
            BN_GF2m_add_original(s, s, h1);
            BN_GF2m_mod_bin_original(s, s, p);
        }
    }
    
    BN_copy(r, s);
}