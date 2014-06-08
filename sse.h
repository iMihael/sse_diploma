#ifndef SSE_H
#define	SSE_H

int xor_bit(int g, int pos1, int pos2);
int set_bit(int t, int pos, int val);
int binary_reduction1(int m, int k3, int k2, int k1, int g);
int binary_reduction2(int m, int k3, int k2, int k1, int g);

int BN_GF2m_add_sse(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_GF2m_add_original(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_GF2m_mod_arr_original(BIGNUM *r, const BIGNUM *a, const int p[]);
int BN_GF2m_mod_original(BIGNUM *r, const BIGNUM *a, const BIGNUM *p);
void BN_GF2m_mod_shrop163(BIGNUM *r, BIGNUM *a);
void BN_GF2m_mod_shrop173(BIGNUM *r, BIGNUM *a);
int BN_set_bit_value(BIGNUM *a, int n, BN_ULONG bit);
void BN_GF2m_mod_bin_original(BIGNUM *r, BIGNUM *a, const int p[]);
void BN_GF2m_mod_bin_sse(BIGNUM *r, BIGNUM *a, const int p[]);
int BN_set_bit_value(BIGNUM *a, int n, BN_ULONG bit);
int binary_mul(int g, int h, int mod);
void BN_GF2m_mod_mul_bin_sse(BIGNUM *r, BIGNUM *g, BIGNUM *h, const int p[]);
void BN_GF2m_mod_mul_bin_original(BIGNUM *r, BIGNUM *g, BIGNUM *h, const int p[]);
void BN_GF2m_mod_shrop503(BIGNUM *r, BIGNUM *a);
void BN_GF2m_mod_shrop509(BIGNUM *r, BIGNUM *a);
void print_pol(const int p[], int n);
void print_BN(BIGNUM * r);
void BN_fx_top(BIGNUM * a);
void BN_GF2m_mod_mul_comb(BIGNUM *r, BIGNUM *g, BIGNUM *h, const int mod[]);
void BN_GF2m_mod_mul_comb_sse(BIGNUM *r, BIGNUM *g, BIGNUM *h, const int mod[]);
void BN_GF2m_mod_shrop509_sse(BIGNUM *r, BIGNUM *a);



#endif	/* SSE_H */

