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
                printf("Usage:\n\n\trainbow-ring-sign message_file_name sk_file_name number_of_users\n\n");
                return -1;
        }

	uint8_t * pk = (uint8_t *) malloc( CRYPTO_PUBLICKEYBYTES );
	uint8_t * pk_1 = (uint8_t *) malloc( CRYPTO_PUBLICKEYBYTES );
	uint8_t *_sk = (uint8_t*)malloc( CRYPTO_SECRETKEYBYTES );

	FILE * fp;
	int r;

	fp = fopen( "pk" , "r");
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

	fp = fopen( "pk1" , "r");
	if( NULL == fp ) {
		printf("fail to open public key file.\n");
		return -1;
	}
	r = byte_fget( fp ,  pk_1 , CRYPTO_PUBLICKEYBYTES );
	fclose( fp );
	if( CRYPTO_PUBLICKEYBYTES != r ) {
		printf("fail to load key file.\n");
		return -1;
	}

	unsigned char * msg = NULL;
	unsigned long long mlen = 0;
	r = byte_read_file( &msg , &mlen , argv[1] );
	if( 0 != r ) {
		printf("fail to read message file.\n");
		return -1;
	}

	fp = fopen( argv[2] , "r");
	if( NULL == fp ) {
		printf("fail to open secret key file.\n");
		return -1;
	}
	r = byte_fget( fp ,  _sk , CRYPTO_SECRETKEYBYTES );
	fclose( fp );
	if( CRYPTO_SECRETKEYBYTES != r ) {
		printf("fail to load key file.\n");
		return -1;
	}

    int users = atoi(argv[3]);

	int row = users;
	int col =  CRYPTO_BYTES + _PUB_M_BYTE; //48
	unsigned char *ptr;
	unsigned char **vector = (unsigned char **)malloc(row * col * sizeof(char) + sizeof(char *) * row);
    srand(2);

	ptr = (unsigned char *)(vector + row);

    int i, j;
	for (i = 0; i < row; i++){
		vector[i] = (ptr + col *i);
	}

	for (i = 0;i < row; i++){
		for (j = 0; j < col;j++){
			vector[i][j] = rand();
		}
	}

	// for (i = 0; i < row; i++){
	// 	for (j = 0;j < col; j++){
	// 		printf("%d ", vector[i][j]);
	// 	}
	// 	printf("\n");
	// }

    uint8_t *pks[] = {pk, pk_1};

	// for (i = 0; i < row; i++){
	// 	for (j = 0; j < col; j++){
	// 		printf("%c ", *(vector + i*col + j));
	// 	}
	// 	printf("\n");
	// }

    // printf("size: %ld \n", sizeof(vector));
    // printf("size of signature: %ld \n", CRYPTO_BYTES);

	int z = crypto_sign_ring(pks, vector, msg, mlen, _sk);
	// printf("%d \n", z);

	if( 0 != z ) {
		printf("sign() fail.\n");
		return -1;
	}

    byte_fdump( stdout , CRYPTO_ALGNAME " signature"  , vector[0], CRYPTO_BYTES + _PUB_M_BYTE);
	printf("\n");
    byte_fdump( stdout , CRYPTO_ALGNAME " signature"  , vector[1], CRYPTO_BYTES + _PUB_M_BYTE);
	printf("\n");

    free( msg );
	// free( signature );
	free( pk );
	free( pk_1 );
	free(_sk);
    free(vector);

    return 0;
}