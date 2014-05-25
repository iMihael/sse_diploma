#ifndef SSE_H
#define	SSE_H

int BN_GF2m_add_sse(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_GF2m_add_original(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_GF2m_mod_arr_original(BIGNUM *r, const BIGNUM *a, const int p[]);
int BN_GF2m_mod_original(BIGNUM *r, const BIGNUM *a, const BIGNUM *p);
int BN_GF2m_mod_shrop(BIGNUM *r, BIGNUM *a);
int BN_set_bit_value(BIGNUM *a, int n, BN_ULONG bit);

#endif	/* SSE_H */

