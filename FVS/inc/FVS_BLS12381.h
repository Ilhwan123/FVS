#ifndef _FVS_BLS12381_H_
#define _FVS_BLS12381_H_

#include "pair_BLS12381.h"
#include "randapi.h"




#define BGS_BLS12381 MODBYTES_384_58  /**< BLS Group Size */
#define BFS_BLS12381 MODBYTES_384_58  /**< BLS Field Size */

#define FVS_OK           1  /**< Function completed without error */
#define FVS_FAIL         0  /**< Point is NOT on the curve */

#define BIO_LEN 2048         /**< Biometric Size*/
#define COMPONENT_SUBSET 80   /**< The Number of Components in Each Subset*/
#define NUMBER_SUBSET 15268   /**< The Number of Subsets*/


typedef struct {
    ECP_BLS12381 G;
    ECP_BLS12381 G1;
    ECP_BLS12381 sp_X[BIO_LEN];
    ECP_BLS12381 sp_Y[BIO_LEN];
} FVS_BLS12381_SIGNING_PARAMETER;


typedef struct {
    ECP2_BLS12381 vk1[NUMBER_SUBSET];
    ECP2_BLS12381 vk2[NUMBER_SUBSET];
    int indset[NUMBER_SUBSET][COMPONENT_SUBSET];
} FVS_BLS12381_VERIFICATION_KEY;

typedef struct {
    ECP_BLS12381 sig1[BIO_LEN];
    ECP_BLS12381 sig2;
    ECP_BLS12381 sig3;
    BIG_384_58 sig4;
    BIG_384_58 sig5;
    ECP_BLS12381 G;
    ECP_BLS12381 G1;
} FVS_BLS12381_SIGNATURE;

typedef struct {
    int bio[BIO_LEN];
} FVS_BIO;



void HASH_BLS12381_FVS(BIG_384_58 out, ECP_BLS12381* g_k, ECP_BLS12381* g1_k, FVS_BLS12381_SIGNATURE* sig);


void FVS_RNG_GENERATE_FROM_TIME(csprng* RNG);

int FVS_BLS12381_SP_VK_GENERATE(FVS_BLS12381_SIGNING_PARAMETER *SP, FVS_BLS12381_VERIFICATION_KEY *VK, csprng* RNG, FVS_BIO *bio);

int FVS_BLS12381_SIGN(FVS_BLS12381_SIGNATURE *sig, FVS_BLS12381_SIGNING_PARAMETER *SP, csprng* RNG, FVS_BIO *bio);

int FVS_BLS12381_VERIFY(FVS_BLS12381_SIGNATURE *sig, FVS_BLS12381_VERIFICATION_KEY *VK);

#endif