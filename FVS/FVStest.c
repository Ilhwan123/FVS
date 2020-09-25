
#include <time.h>
#include "FVS_BLS12381.h"
#include "string.h"



int main()
{
	int i;
	int signok;
	int verifyok;
	int isSame;
	int tenperlen = BIO_LEN / 10;
	int count = 0;
	int save[tenperlen];
	int tmp;
	
	

	csprng RNG;
	srand(time(0));
	clock_t st1, et1, st2, et2, st3, et3, st4, et4, st5, et5;
	
	
	FVS_BLS12381_SIGNING_PARAMETER sp;
	FVS_BLS12381_VERIFICATION_KEY vk;
	FVS_BLS12381_SIGNATURE sig5;
	FVS_BLS12381_SIGNATURE sig10;
	FVS_BIO bio;
	FVS_BIO bio5;
	FVS_BIO bio10;

	
	for(i = 0 ; i < BIO_LEN ; i++)
	{
		bio.bio[i] = rand() % 2;
		bio5.bio[i] = bio.bio[i];
		bio10.bio[i] = bio.bio[i];
	}

	// randomly select error part
	while (count < tenperlen) {
        isSame = 0;
        tmp = rand() % BIO_LEN;
        for (i = 0; i < count; i++) { 
            if (tmp == save[i]) { 
                isSame = 1;
                break;
            }
        }
        if (isSame == 0) { 
            save[count] = tmp;
            count++;
        }
    }

    // adding 10% error to bio readings
    for(i = 0 ; i < tenperlen ; i++)
    {
    	if (bio10.bio[save[i]] == 0)
    		bio10.bio[save[i]] = 1;
    	else bio10.bio[save[i]] = 0;
    }

    // adding 5% error to bio readings
    for(i = 0 ; i < tenperlen / 2 ; i++)
    {
    	if (bio5.bio[save[i]] == 0)
    		bio5.bio[save[i]] = 1;
    	else bio5.bio[save[i]] = 0;
    }




	FVS_RNG_GENERATE_FROM_TIME(&RNG);

	st1 = clock();
	FVS_BLS12381_SP_VK_GENERATE(&sp, &vk, &RNG, &bio);
	et1 = clock();
	printf("Setup Time: %lf s\n", (double)(et1 - st1)/CLOCKS_PER_SEC);


	st2 = clock();
	signok = FVS_BLS12381_SIGN(&sig5, &sp, &RNG, &bio5);
	et2 = clock();
	if (signok == FVS_OK) printf("Sign 5 : success\n");
	printf("Sign 5 Time: %lf s\n", (double)(et2 - st2)/CLOCKS_PER_SEC);


	st3 = clock();
	signok = FVS_BLS12381_SIGN(&sig10, &sp, &RNG, &bio10);
	et3 = clock();
	if (signok == FVS_OK) printf("Sign 10 : success\n");
	printf("Sign 10 Time: %lf s\n", (double)(et3 - st3)/CLOCKS_PER_SEC);


	st4 = clock();
	verifyok = FVS_BLS12381_VERIFY(&sig5, &vk);
	et4 = clock();
	if (verifyok == FVS_OK) printf("Verify 5 : success\n");
	printf("Verify 5 Time: %lf s\n", (double)(et4 - st4)/CLOCKS_PER_SEC);


	st5 = clock();
	verifyok = FVS_BLS12381_VERIFY(&sig10, &vk);
	et5 = clock();
	if (verifyok == FVS_OK) printf("Verify 10 : success\n");
	printf("Verify 10 Time: %lf s\n", (double)(et5 - st5)/CLOCKS_PER_SEC);



}


