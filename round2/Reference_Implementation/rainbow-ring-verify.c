///  @file rainbow-verify.c
///  @brief A command-line tool for verifying a signature.
///

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "rainbow_config.h"

#include "utils.h"

#include "api.h"
#define RING_NAME "RING RAINBOW"

int main( int argc , char ** argv )
{ 
	printf( "%s\n", RING_NAME );

        printf("sk size: %lu\n", CRYPTO_SECRETKEYBYTES );
        printf("pk size: %lu\n",  CRYPTO_PUBLICKEYBYTES );
        printf("hash size: %d\n", _HASH_LEN );
        printf("signature size: %d\n\n", CRYPTO_BYTES );

	if( 4 != argc ) {
                printf("Usage:\n\n\trainbow-ring-verify signature_file_name message_file_name number_of_users\n\n");
                return -1;
        }
	
    int users = atoi(argv[3]);


	uint8_t * pk = (uint8_t *) malloc( CRYPTO_PUBLICKEYBYTES );
	uint8_t *ptrx;
    uint8_t **pks = (uint8_t **)malloc(users * CRYPTO_PUBLICKEYBYTES * sizeof(uint8_t) + sizeof(uint8_t *) * users);;

	ptrx = (uint8_t *)(pks + users);

	int k;
	for (k = 0; k < users; k++){
		pks[k] = (ptrx + CRYPTO_PUBLICKEYBYTES *k);
	}

	FILE * fp;
	int r;

    char x[4];
    // char d[2];

    strcat(x, "pk");

    for (int i = 0; i < users; i++){
		char *d = (char *) malloc(1);
        if (i == 0){
            // printf("Here\n");
            fp = fopen("pk", "r");
        } else {
            // printf("Here");
            sprintf(d, "%d", i);
			 x[2] = d[0];
            // strcat(x, d);
            fp = fopen(x, "r");
        }

        if( NULL == fp ) {
		    printf("fail to open public key file.\n");
		    return -1;
        }
        r = byte_fget( fp ,  pk , CRYPTO_PUBLICKEYBYTES );
	    fclose( fp );
	    if( CRYPTO_PUBLICKEYBYTES != r ) {
		    printf("fail to load key file.\n");
		    return -1;
	    }

		int a;
        for (a = 0; a < CRYPTO_PUBLICKEYBYTES; a++){
            pks[i][a] = pk[a];
        }

		// printf("%2x ", pks[0][0]);
        // free(pk);
		free(d);
    }


	// uint8_t * pk_1 = (uint8_t *) malloc( CRYPTO_PUBLICKEYBYTES );

	// FILE * fp;
	// int r;

	// fp = fopen( "pk" , "r");
	// if( NULL == fp ) {
	// 	printf("fail to open public key file.\n");
	// 	return -1;
	// }
	// r = byte_fget( fp ,  pk , CRYPTO_PUBLICKEYBYTES );
	// fclose( fp );
	// if( CRYPTO_PUBLICKEYBYTES != r ) {
	// 	printf("fail to load key file.\n");
	// 	return -1;
	// }

	// fp = fopen( "pk1" , "r");
	// if( NULL == fp ) {
	// 	printf("fail to open public key file.\n");
	// 	return -1;
	// }
	// r = byte_fget( fp ,  pk_1 , CRYPTO_PUBLICKEYBYTES );
	// fclose( fp );
	// if( CRYPTO_PUBLICKEYBYTES != r ) {
	// 	printf("fail to load key file.\n");
	// 	return -1;
	// }

	unsigned char * msg = NULL;
	unsigned long long mlen = 0;
	r = byte_read_file( &msg , &mlen , argv[2] );
	if( 0 != r ) {
		printf("fail to read message file.\n");
		return -1;
	}

	unsigned char *ptrs;
	unsigned char **signatures =  (char **)malloc(users * (CRYPTO_BYTES + _PUB_M_BYTE) * sizeof(char) + sizeof(char *) * users);

	ptrs = (char *)(signatures + users);

	int t;
	for (t = 0; t < users; t++){
		signatures[t] = (ptrs + (CRYPTO_BYTES + _PUB_M_BYTE) *t);
	}

	unsigned char * signature1 = malloc(CRYPTO_BYTES + _PUB_M_BYTE + mlen);
	int j;
	for (j = 0; j < users; j ++){
		if( NULL == signature1 ) {
			printf("alloc memory for signature buffer fail.\n");
			return -1;
		}
		memcpy( signature1 , msg , mlen );
		fp = fopen( argv[1] , "r");
		if( NULL == fp ) {
			printf("fail to open signature file.\n");
			return -1;
		}

		if (j != 0) {
			char c = 0;
    		while( EOF != c ) {
	    		c = fgetc( fp );
				if( ('=' == c) ) break;
			}
			fseek(fp, (CRYPTO_BYTES + _PUB_M_BYTE + mlen) * j , SEEK_CUR);
		}

		r = byte_fget( fp ,  signature1 + mlen, CRYPTO_BYTES + _PUB_M_BYTE);
		fclose( fp );
		if( CRYPTO_BYTES + _PUB_M_BYTE != r ) {
			printf("fail to load signature file.\n");
			return -1;
		}
		int a;
		for (a = 0; a <(CRYPTO_BYTES + _PUB_M_BYTE); a ++){
			signatures[j][a] = signature1[mlen + a];
		}
		
	}
	// unsigned char * signature1 = malloc(CRYPTO_BYTES + _PUB_M_BYTE + mlen);
	// if( NULL == signature1 ) {
	// 	printf("alloc memory for signature buffer fail.\n");
	// 	return -1;
	// }
	// memcpy( signature1 , msg , mlen );
	// fp = fopen( argv[1] , "r");
	// if( NULL == fp ) {
	// 	printf("fail to open signature file.\n");
	// 	return -1;
	// }
	// r = byte_fget( fp ,  signature1 + mlen, CRYPTO_BYTES + _PUB_M_BYTE);
	// fclose( fp );
	// if( CRYPTO_BYTES + _PUB_M_BYTE != r ) {
	// 	printf("fail to load signature file.\n");
	// 	return -1;
	// }

    
	// unsigned char * signature2 = malloc(CRYPTO_BYTES + _PUB_M_BYTE + mlen);
	// if( NULL == signature2 ) {
	// 	printf("alloc memory for signature buffer fail.\n");
	// 	return -1;
	// }
	// memcpy( signature2 , msg , mlen );
	// fp = fopen( argv[1] , "r");
	// if( NULL == fp ) {
	// 	printf("fail to open signature file.\n");
	// 	return -1;
	// }

    // char c = 0;
    // while( EOF != c ) {
	//     c = fgetc( fp );
	// 	if( ('=' == c) ) break;
	// }

    // fseek(fp, CRYPTO_BYTES + _PUB_M_BYTE + mlen ,SEEK_CUR);

    // r = byte_fget( fp ,  signature2 + mlen, CRYPTO_BYTES + _PUB_M_BYTE);
	// fclose( fp );
	// if( CRYPTO_BYTES + _PUB_M_BYTE != r ) {
	// 	printf("fail to load signature file.\n");
	// 	return -1;
	// }

    // int users = atoi(argv[3]);

    // printf("Signature1: \n");

    // for (int i = 0; i < CRYPTO_BYTES + _PUB_M_BYTE ; i++){
    //     printf("%d ", signature1[i + mlen]);
    // }

    // printf("\n");

    // printf("Signature2: \n");

    // for (int i = 0; i < CRYPTO_BYTES + _PUB_M_BYTE ; i++){
    //     printf("%d ", signature2[i + mlen]);
    // }

    // printf("\n");
    // printf("Number of users: %d\n", users);

	// r = crypto_sign_open( msg , &mlen , signature , mlen + CRYPTO_BYTES , pk );


	// int row = users;
	// int col =  CRYPTO_BYTES + _PUB_M_BYTE; //48 ??????
	// unsigned char *ptr;
	// unsigned char **vector = (unsigned char **)malloc(row * col * sizeof(char) + sizeof(char *) * row);

    printf("Signature1: \n");
    for (int i = 0; i < CRYPTO_BYTES + _PUB_M_BYTE ; i++){
        printf("%02x ", signatures[0][i]);
    }

    printf("\n");

	printf("Signature2: \n");
    for (int i = 0; i < CRYPTO_BYTES + _PUB_M_BYTE ; i++){
        printf("%02x ", signatures[1][i]);
    }

    printf("\n");

	int z = rainbow_verify_ring(pks, signatures, msg, &mlen, mlen + CRYPTO_BYTES, users);
	printf("%d \n", z);
	if( 0 == z ) {
		printf("Correctly verified.\n" );
		return 0;
	} else {
		printf("Verification fails.\n" );
		return -1;
	}

    free( msg );
	// free( signature );
	free( pk );
	// free( pk_1 );
    // free(vector);

    return 0;
}