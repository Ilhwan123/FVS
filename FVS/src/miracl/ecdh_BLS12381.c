/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* ECDH/ECIES/ECDSA Functions - see main program below */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "ecdh_BLS12381.h"

/* Calculate a public/private EC GF(p) key pair. W=S.G mod EC(p),
 * where S is the secret key and W is the public key
 * and G is fixed generator.
 * If RNG is NULL then the private key is provided externally in S
 * otherwise it is generated randomly internally */
int ECP_BLS12381_KEY_PAIR_GENERATE(csprng *RNG, octet* S, octet *W)
{
    BIG_384_58 r, s;
    ECP_BLS12381 G;
    int res = 0;

    ECP_BLS12381_generator(&G);

    BIG_384_58_rcopy(r, CURVE_Order_BLS12381);
    if (RNG != NULL)
    {
        BIG_384_58_randtrunc(s, r, 2 * CURVE_SECURITY_BLS12381, RNG);
    }
    else
    {
        BIG_384_58_fromBytes(s, S->val);
        BIG_384_58_mod(s, r);
    }

#ifdef AES_S
    BIG_384_58_mod2m(s, 2 * AES_S);
#endif

    S->len = EGS_BLS12381;
    BIG_384_58_toBytes(S->val, s);

    ECP_BLS12381_mul(&G, s);

    ECP_BLS12381_toOctet(W, &G, false); /* To use point compression on public keys, change to true */

    return res;
}

/* Validate public key */
int ECP_BLS12381_PUBLIC_KEY_VALIDATE(octet *W)
{
    BIG_384_58 q, r, k;
    ECP_BLS12381 WP;
    int valid, nb;
    int res = 0;

    BIG_384_58_rcopy(q, Modulus_BLS12381);
    BIG_384_58_rcopy(r, CURVE_Order_BLS12381);

    valid = ECP_BLS12381_fromOctet(&WP, W);
    if (!valid) res = ECDH_INVALID_PUBLIC_KEY;

    if (res == 0)
    {   /* Check point is not in wrong group */
        nb = BIG_384_58_nbits(q);
        BIG_384_58_one(k);
        BIG_384_58_shl(k, (nb + 4) / 2);
        BIG_384_58_add(k, q, k);
        BIG_384_58_sdiv(k, r); /* get co-factor */

        while (BIG_384_58_parity(k) == 0)
        {
            ECP_BLS12381_dbl(&WP);
            BIG_384_58_fshr(k, 1);
        }

        if (!BIG_384_58_isunity(k)) ECP_BLS12381_mul(&WP, k);
        if (ECP_BLS12381_isinf(&WP)) res = ECDH_INVALID_PUBLIC_KEY;
    }

    return res;
}

/* IEEE-1363 Diffie-Hellman online calculation Z=S.WD */
int ECP_BLS12381_SVDP_DH(octet *S, octet *WD, octet *Z)
{
    BIG_384_58 r, s, wx;
    int valid;
    ECP_BLS12381 W;
    int res = 0;

    BIG_384_58_fromBytes(s, S->val);

    valid = ECP_BLS12381_fromOctet(&W, WD);

    if (!valid) res = ECDH_ERROR;
    if (res == 0)
    {
        BIG_384_58_rcopy(r, CURVE_Order_BLS12381);
        BIG_384_58_mod(s, r);

        ECP_BLS12381_mul(&W, s);
        if (ECP_BLS12381_isinf(&W)) res = ECDH_ERROR;
        else
        {
#if CURVETYPE_BLS12381!=MONTGOMERY
            ECP_BLS12381_get(wx, wx, &W);
#else
            ECP_BLS12381_get(wx, &W);
#endif
            Z->len = MODBYTES_384_58;
            BIG_384_58_toBytes(Z->val, wx);
        }
    }
    return res;
}

#if CURVETYPE_BLS12381!=MONTGOMERY

/* IEEE ECDSA Signature, C and D are signature on F using private key S */
int ECP_BLS12381_SP_DSA(int hlen, csprng *RNG, octet *K, octet *S, octet *F, octet *C, octet *D)
{
    char h[128];
    octet H = {0, sizeof(h), h};

    BIG_384_58 r, s, f, c, d, u, vx, w;
    ECP_BLS12381 G, V;

    SPhash(MC_SHA2, hlen, &H, F);

    ECP_BLS12381_generator(&G);

    BIG_384_58_rcopy(r, CURVE_Order_BLS12381);

    BIG_384_58_fromBytes(s, S->val);

    int blen = H.len;
    if (H.len > MODBYTES_384_58) blen = MODBYTES_384_58;
    BIG_384_58_fromBytesLen(f, H.val, blen);

    if (RNG != NULL)
    {
        do
        {
            BIG_384_58_randomnum(u, r, RNG);
            BIG_384_58_randomnum(w, r, RNG); /* side channel masking */

#ifdef AES_S
            BIG_384_58_mod2m(u, 2 * AES_S);
#endif
            ECP_BLS12381_copy(&V, &G);
            ECP_BLS12381_mul(&V, u);

            ECP_BLS12381_get(vx, vx, &V);

            BIG_384_58_copy(c, vx);
            BIG_384_58_mod(c, r);
            if (BIG_384_58_iszilch(c)) continue;

            BIG_384_58_modmul(u, u, w, r);

            BIG_384_58_invmodp(u, u, r);
            BIG_384_58_modmul(d, s, c, r);

            BIG_384_58_add(d, f, d);

            BIG_384_58_modmul(d, d, w, r);

            BIG_384_58_modmul(d, u, d, r);
        } while (BIG_384_58_iszilch(d));
    }
    else
    {
        BIG_384_58_fromBytes(u, K->val);
        BIG_384_58_mod(u, r);

#ifdef AES_S
        BIG_384_58_mod2m(u, 2 * AES_S);
#endif
        ECP_BLS12381_copy(&V, &G);
        ECP_BLS12381_mul(&V, u);

        ECP_BLS12381_get(vx, vx, &V);

        BIG_384_58_copy(c, vx);
        BIG_384_58_mod(c, r);
        if (BIG_384_58_iszilch(c)) return ECDH_ERROR;


        BIG_384_58_invmodp(u, u, r);
        BIG_384_58_modmul(d, s, c, r);

        BIG_384_58_add(d, f, d);

        BIG_384_58_modmul(d, u, d, r);
        if (BIG_384_58_iszilch(d)) return ECDH_ERROR;
    }

    C->len = D->len = EGS_BLS12381;

    BIG_384_58_toBytes(C->val, c);
    BIG_384_58_toBytes(D->val, d);

    return 0;
}

/* IEEE1363 ECDSA Signature Verification. Signature C and D on F is verified using public key W */
int ECP_BLS12381_VP_DSA(int hlen, octet *W, octet *F, octet *C, octet *D)
{
    char h[128];
    octet H = {0, sizeof(h), h};

    BIG_384_58 r, f, c, d, h2;
    int res = 0;
    ECP_BLS12381 G, WP;
    int valid;

    SPhash(MC_SHA2, hlen, &H, F);

    ECP_BLS12381_generator(&G);

    BIG_384_58_rcopy(r, CURVE_Order_BLS12381);

    OCT_shl(C, C->len - MODBYTES_384_58);
    OCT_shl(D, D->len - MODBYTES_384_58);

    BIG_384_58_fromBytes(c, C->val);
    BIG_384_58_fromBytes(d, D->val);

    int blen = H.len;
    if (blen > MODBYTES_384_58) blen = MODBYTES_384_58;

    BIG_384_58_fromBytesLen(f, H.val, blen);

    //BIG_fromBytes(f,H.val);

    if (BIG_384_58_iszilch(c) || BIG_384_58_comp(c, r) >= 0 || BIG_384_58_iszilch(d) || BIG_384_58_comp(d, r) >= 0)
        res = ECDH_ERROR;

    if (res == 0)
    {
        BIG_384_58_invmodp(d, d, r);
        BIG_384_58_modmul(f, f, d, r);
        BIG_384_58_modmul(h2, c, d, r);

        valid = ECP_BLS12381_fromOctet(&WP, W);

        if (!valid) res = ECDH_ERROR;
        else
        {
            ECP_BLS12381_mul2(&WP, &G, h2, f);

            if (ECP_BLS12381_isinf(&WP)) res = ECDH_ERROR;
            else
            {
                ECP_BLS12381_get(d, d, &WP);
                BIG_384_58_mod(d, r);
                if (BIG_384_58_comp(d, c) != 0) res = ECDH_ERROR;
            }
        }
    }

    return res;
}

/* IEEE1363 ECIES encryption. Encryption of plaintext M uses public key W and produces ciphertext V,C,T */
void ECP_BLS12381_ECIES_ENCRYPT(int hlen, octet *P1, octet *P2, csprng *RNG, octet *W, octet *M, int tlen, octet *V, octet *C, octet *T)
{

    int i, len;
    char z[EFS_BLS12381], vz[3 * EFS_BLS12381 + 1], k[2 * AESKEY_BLS12381], k1[AESKEY_BLS12381], k2[AESKEY_BLS12381], l2[8], u[EFS_BLS12381];
    octet Z = {0, sizeof(z), z};
    octet VZ = {0, sizeof(vz), vz};
    octet K = {0, sizeof(k), k};
    octet K1 = {0, sizeof(k1), k1};
    octet K2 = {0, sizeof(k2), k2};
    octet L2 = {0, sizeof(l2), l2};
    octet U = {0, sizeof(u), u};

    if (ECP_BLS12381_KEY_PAIR_GENERATE(RNG, &U, V) != 0) return;
    if (ECP_BLS12381_SVDP_DH(&U, W, &Z) != 0) return;

    OCT_copy(&VZ, V);
    OCT_joctet(&VZ, &Z);

    KDF2(MC_SHA2, hlen, &K, 2 * AESKEY_BLS12381, &VZ, P1);

    K1.len = K2.len = AESKEY_BLS12381;
    for (i = 0; i < AESKEY_BLS12381; i++)
    {
        K1.val[i] = K.val[i];
        K2.val[i] = K.val[AESKEY_BLS12381 + i];
    }

    AES_CBC_IV0_ENCRYPT(&K1, M, C);

    OCT_jint(&L2, P2->len, 8);

    len = C->len;
    OCT_joctet(C, P2);
    OCT_joctet(C, &L2);
    HMAC(MC_SHA2, hlen, T, tlen, C, &K2);
    C->len = len;
}

/* IEEE1363 ECIES decryption. Decryption of ciphertext V,C,T using private key U outputs plaintext M */
int ECP_BLS12381_ECIES_DECRYPT(int hlen, octet *P1, octet *P2, octet *V, octet *C, octet *T, octet *U, octet *M)
{

    int i, len;
    char z[EFS_BLS12381], vz[3 * EFS_BLS12381 + 1], k[2 * AESKEY_BLS12381], k1[AESKEY_BLS12381], k2[AESKEY_BLS12381], l2[8], tag[32];
    octet Z = {0, sizeof(z), z};
    octet VZ = {0, sizeof(vz), vz};
    octet K = {0, sizeof(k), k};
    octet K1 = {0, sizeof(k1), k1};
    octet K2 = {0, sizeof(k2), k2};
    octet L2 = {0, sizeof(l2), l2};
    octet TAG = {0, sizeof(tag), tag};

    if (ECP_BLS12381_SVDP_DH(U, V, &Z) != 0) return 0;

    OCT_copy(&VZ, V);
    OCT_joctet(&VZ, &Z);

    KDF2(MC_SHA2, hlen, &K, 2 * AESKEY_BLS12381, &VZ, P1);

    K1.len = K2.len = AESKEY_BLS12381;
    for (i = 0; i < AESKEY_BLS12381; i++)
    {
        K1.val[i] = K.val[i];
        K2.val[i] = K.val[AESKEY_BLS12381 + i];
    }

    if (!AES_CBC_IV0_DECRYPT(&K1, C, M)) return 0;

    OCT_jint(&L2, P2->len, 8);

    len = C->len;
    OCT_joctet(C, P2);
    OCT_joctet(C, &L2);
    HMAC(MC_SHA2, hlen, &TAG, T->len, C, &K2);
    C->len = len;

    if (!OCT_ncomp(T, &TAG, T->len)) return 0;

    return 1;

}

#endif
