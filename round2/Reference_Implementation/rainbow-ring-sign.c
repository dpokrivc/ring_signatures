
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "Ia_Classic/rainbow_config.h"

#include "Ia_Classic/utils.h"

#include "Ia_Classic/rng.h"

#include "Ia_Classic/api.h"

int main(int argc, char **argv)
{
    unsigned char vector[16];
    srand(2);

    int i;
    for (i = 0; i < 16; i++)
    {
        vector[i] = rand();
        printf("%d ", vector[i]);
    }

    printf("size: %ld \n", sizeof(vector));
    printf("size of signature: %ld \n", CRYPTO_BYTES);


    uint8_t *pk = (uint8_t *)malloc(CRYPTO_PUBLICKEYBYTES);

    FILE *fp;
    int r;

    fp = fopen(argv[1], "r");
    if (NULL == fp)
    {
        printf("fail to open public key file.\n");
        return -1;
    }


    // r = byte_fget(fp, pk, CRYPTO_PUBLICKEYBYTES);

    // if (CRYPTO_SECRETKEYBYTES != r)
    // {
    //     printf("fail to load key file.\n");
    //     return -1;
    // }

    // r = crypto_sign_ring(pk, vector);

    printf("Here: %d \n", r);
}