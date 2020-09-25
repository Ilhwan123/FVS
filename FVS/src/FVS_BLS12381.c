#include <string.h>
#include <time.h>


#include "FVS_BLS12381.h"



void HASH_BLS12381_FVS(BIG_384_58 out, ECP_BLS12381* g_k, ECP_BLS12381* g1_k, FVS_BLS12381_SIGNATURE* sig)
{
    BIG_384_58 q;
    BIG_384_58 tmp;

    unsigned char element[49] = {0};

    unsigned char* message;
    unsigned char digest[48] = {0};
 
    octet Element = {0, 49, element};
    octet Message;
    octet Digest  = {0, 32, digest};

    //Initialize Message
    message = (unsigned char*) malloc((BIO_LEN + 2)*49);
    Message.len = (BIO_LEN + 2)*49;
    Message.val = message;
    Message.max = (BIO_LEN + 2)*49;

    ECP_BLS12381_toOctet(&Element, g_k, 1);
    memcpy(message + 0 * 49, element, 49);

    ECP_BLS12381_toOctet(&Element, g1_k, 1);
    memcpy(message + 1 * 49, element, 49);


    for (int i = 0; i < BIO_LEN; i++)
    {
        ECP_BLS12381_toOctet(&Element, sig->sig1 + i, 1);
        memcpy(message + (i + 2) * 49, element, 49);

    }

    SPhash(MC_SHA2, 32, &Digest, &Message);

    BIG_384_58_fromBytesLen(tmp, Digest.val, Digest.len);

    BIG_384_58_rcopy(q, CURVE_Order_BLS12381);

    BIG_384_58_mod(tmp, q);

    BIG_384_58_copy(out, tmp);

    free(message);
}





void FVS_RNG_GENERATE_FROM_TIME(csprng* RNG)
{
    int i, count=0;
    unsigned long ran;
    char raw[100];    

    //=================================== Generating RNG ===================================
    octet RAW = {0, sizeof(char)*BGS_BLS12381, raw};

    time((time_t *)&ran);
    
    RAW.len = 100;              // fake random seed source
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (i = 4; i < 100; i++) RAW.val[i] = i;

    CREATE_CSPRNG(RNG, &RAW);  // initialise strong RNG
    //================================= Generating RNG End =================================
}





int FVS_BLS12381_SP_VK_GENERATE(FVS_BLS12381_SIGNING_PARAMETER *SP, FVS_BLS12381_VERIFICATION_KEY *VK, csprng* RNG, FVS_BIO *bio){
    int i,j,tmp;
    
    int save[COMPONENT_SUBSET];
    int count = 0;
    int isSame = 0;
    srand(time(0));

    
    BIG_384_58 q;
    BIG_384_58 ran;
    ECP_BLS12381 G;
    ECP_BLS12381 G1;
    ECP2_BLS12381 G2;

    BIG_384_58 *x= malloc( BIO_LEN * sizeof(BIG_384_58));
    ECP_BLS12381 *X1= malloc( BIO_LEN * sizeof(ECP_BLS12381));


    BIG_384_58 *y = malloc( BIO_LEN * sizeof(BIG_384_58));
    ECP_BLS12381 *Y1 = malloc( BIO_LEN * sizeof(ECP_BLS12381));


    BIG_384_58 *r = malloc( NUMBER_SUBSET * sizeof(BIG_384_58));
    ECP2_BLS12381 *V = malloc( BIO_LEN * sizeof(ECP2_BLS12381));
    ECP2_BLS12381 *V1 = malloc( NUMBER_SUBSET * sizeof(ECP2_BLS12381));
    ECP2_BLS12381 *V2 = malloc( NUMBER_SUBSET * sizeof(ECP2_BLS12381));
    
      

    //================================ Generating Signing Parameter ==============================

    BIG_384_58_rcopy(q, CURVE_Order_BLS12381);
    BIG_384_58_randomnum(ran, q, RNG);

    for (i = 0; i < BIO_LEN; i++) 
    {
        BIG_384_58_randomnum(x[i], q, RNG);
    }

    for (i = 0; i < BIO_LEN; i++) 
    {
        BIG_384_58_randomnum(y[i], q, RNG);
    }

    if (!ECP_BLS12381_generator(&G)) return FVS_FAIL;
    if (!ECP2_BLS12381_generator(&G2)) return FVS_FAIL;

    ECP_BLS12381_copy(&G1, &G);
    ECP_BLS12381_mul(&G1, ran);

    //X1_n=(x_n)G1
    for (i = 0; i < BIO_LEN; i++) 
    {
        ECP_BLS12381_copy(&X1[i], &G);
        ECP_BLS12381_mul(&X1[i], x[i]);
    }


    //Y1_n=(y_n)G1
    for (i = 0; i < BIO_LEN; i++) 
    {
        ECP_BLS12381_copy(&Y1[i], &G);
        ECP_BLS12381_mul(&Y1[i], y[i]);
    }
    

    ECP_BLS12381_copy(&SP->G, &G);
    ECP_BLS12381_copy(&SP->G1, &G1);


    for (i = 0; i < BIO_LEN; i++) 
    {
        ECP_BLS12381_copy(SP->sp_X + i, &X1[i]);
        ECP_BLS12381_copy(SP->sp_Y + i, &Y1[i]);
    }


    //============================== Generating Signing Parameter End =============================


    //================================= Generating Verification Key ===============================
       

    for (i = 0; i < BIO_LEN; i++) 
    {
        if (bio->bio[i]==1)
            BIG_384_58_add(x[i], x[i], y[i]);
    }

    //V_i=(x_i + bio y_i)G2
    for (i = 0; i < BIO_LEN; i++) 
    {
        ECP2_BLS12381_copy(&V[i], &G2);
        ECP2_BLS12381_mul(&V[i], x[i]);
    }
  

    for (i = 0; i < NUMBER_SUBSET; i++) 
    {
        BIG_384_58_randomnum(r[i], q, RNG);
        count = 0;
    
        //숫자 추출
        while (count < COMPONENT_SUBSET) {
            isSame = 0;
            tmp = rand() % BIO_LEN;//1부터 80 출력
            for (j = 0; j < count; j++) { //중복검사
                if (tmp == save[j]) { //중복이 있을때
                    isSame = 1;
                    break;
                }
            }
            if (isSame == 0) { //중복없음
                save[count] = tmp;
                count++;
            }
        }

        ECP2_BLS12381_copy(&V1[i], &V[save[0]]);
        

        for (j = 1 ; j < COMPONENT_SUBSET; j++)
        {
            ECP2_BLS12381_add(&V1[i], &V[save[j]]);
        }
        ECP2_BLS12381_mul(&V1[i], r[i]);

        for (j = 0 ; j < COMPONENT_SUBSET; j++)
        {
            VK->indset[i][j]=save[j];
        }
    }

    

    //V2_j=(r_j)G2
    for (i = 0; i < NUMBER_SUBSET; i++) 
    {
        ECP2_BLS12381_copy(&V2[i], &G2);
        ECP2_BLS12381_mul(&V2[i], r[i]);
    }

    

    for (i = 0; i < NUMBER_SUBSET; i++) 
    {
        ECP2_BLS12381_copy(VK->vk1 + i, &V1[i]);
        ECP2_BLS12381_copy(VK->vk2 + i, &V2[i]);
    }

   

    



    //============================== Generating Verification Key End =============================



    free(x);
    free(y);
    free(X1);
    free(Y1);
    free(V);
    free(V1);
    free(V2);
    free(r);
    
    
    return FVS_OK;
}


int FVS_BLS12381_SIGN(FVS_BLS12381_SIGNATURE *sig, FVS_BLS12381_SIGNING_PARAMETER *SP, csprng* RNG, FVS_BIO *bio){

    int i;

    BIG_384_58 s; 
    BIG_384_58 k;
    BIG_384_58 q;
    BIG_384_58 out;

    ECP_BLS12381 G;
    ECP_BLS12381 G1;

    ECP_BLS12381 g_k;
    ECP_BLS12381 g1_k;

    ECP_BLS12381 *Sg1= malloc( BIO_LEN * sizeof(ECP_BLS12381));
    ECP_BLS12381 Sg2;
    ECP_BLS12381 Sg3;
    BIG_384_58 Sg4;
    BIG_384_58 Sg5;


    BIG_384_58_rcopy(q, CURVE_Order_BLS12381);
    BIG_384_58_randomnum(s, q, RNG);
    BIG_384_58_randomnum(k, q, RNG);

    ECP_BLS12381_copy(&G, &SP->G);
    ECP_BLS12381_copy(&G1, &SP->G1);

    for(i = 0 ; i < BIO_LEN ; i++)
    {
        ECP_BLS12381_copy(&Sg1[i], &SP->sp_X[i]);

        if (bio->bio[i]==1)
        {
            ECP_BLS12381_add(&Sg1[i], &SP->sp_Y[i]);
        }

        ECP_BLS12381_mul(&Sg1[i], s);
        ECP_BLS12381_copy(sig->sig1 + i, &Sg1[i]);
    }

    ECP_BLS12381_copy(&Sg2, &G);
    ECP_BLS12381_copy(&Sg3, &G1);

    ECP_BLS12381_mul(&Sg2, s);
    ECP_BLS12381_mul(&Sg3, s);

    ECP_BLS12381_copy(&g_k, &G);
    ECP_BLS12381_copy(&g1_k, &G1);

    ECP_BLS12381_mul(&g_k, k);
    ECP_BLS12381_mul(&g1_k, k);

/*
    

    for (i = 0; i < BIO_LEN; i++) 
    {
        ECP_BLS12381_copy(sig->sig1 + i, &Sg1[i]);
    }
  */
    
    ECP_BLS12381_copy(&sig->sig2, &Sg2);
    ECP_BLS12381_copy(&sig->sig3, &Sg3);


    HASH_BLS12381_FVS(Sg4, &g_k, &g1_k, sig);


    BIG_384_58_copy(Sg5, Sg4);

    BIG_384_58_smul(Sg5, Sg5, s);
    BIG_384_58_add(Sg5, Sg5, k);

    ECP_BLS12381_copy(&sig->G, &G);
    ECP_BLS12381_copy(&sig->G1, &G1);



    BIG_384_58_copy(sig->sig4, Sg4);
    BIG_384_58_copy(sig->sig5, Sg5);


    free(Sg1);

    return FVS_OK;

}



int FVS_BLS12381_VERIFY(FVS_BLS12381_SIGNATURE *sig, FVS_BLS12381_VERIFICATION_KEY *VK){

    int i, j;
    int count = 0;

    BIG_384_58 q;
    BIG_384_58 is4; // inverse of sig4
    BIG_384_58 hout;
    
    ECP_BLS12381 A;
    ECP_BLS12381 B;
    ECP_BLS12381 B1;
    ECP_BLS12381 BB;
    ECP_BLS12381 BB1;
    
    FP12_BLS12381 v1;
    FP12_BLS12381 v2;


    BIG_384_58_rcopy(q, CURVE_Order_BLS12381);

    for (i = 0 ; i < NUMBER_SUBSET ; i++)
    {
        ECP_BLS12381_copy(&A, &sig->sig1[VK->indset[i][0]]);
        
        for (j = 1 ; j < COMPONENT_SUBSET ; j++)
        {
            ECP_BLS12381_add(&A, &sig->sig1[VK->indset[i][j]]);
        }

        PAIR_BLS12381_ate(&v1, VK->vk1 + i, &sig->sig2);
        PAIR_BLS12381_ate(&v2, VK->vk2 + i, &A);

        PAIR_BLS12381_fexp(&v1);
        PAIR_BLS12381_fexp(&v2);

        if (FP12_BLS12381_equals(&v1, &v2)==1)
        {
            count = 1;
            printf("i = %d\n", i);
            break;
        }

    }

    if (count == 0)
    {
        printf("count=0\n");
        return FVS_FAIL;
    }



    ECP_BLS12381_copy(&B, &sig->G);
    ECP_BLS12381_copy(&B1, &sig->G1);
    ECP_BLS12381_copy(&BB, &sig->sig2);
    ECP_BLS12381_copy(&BB1, &sig->sig3);

    ECP_BLS12381_mul(&B, sig->sig5);
    ECP_BLS12381_mul(&B1, sig->sig5);

    BIG_384_58_sub(is4, q, sig->sig4);

    ECP_BLS12381_mul(&BB, is4);
    ECP_BLS12381_mul(&BB1, is4);

    ECP_BLS12381_add(&B, &BB);
    ECP_BLS12381_add(&B1, &BB1);

    HASH_BLS12381_FVS(hout, &B, &B1, sig);



    if(BIG_384_58_comp(hout, sig->sig4)!=0)
    {

        printf("hash error\n");
        return FVS_FAIL;
    }


    return FVS_OK;

}