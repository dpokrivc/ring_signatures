///  @file  sign.c
///  @brief the implementations for functions in api.h
///
///
#include <stdlib.h>
#include <string.h>

#include "rainbow_config.h"
#include "rainbow_keypair.h"
#include "rainbow.h"

#include "api.h"

#include "utils_hash.h"

#include <rng.h>




int
crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    unsigned char sk_seed[LEN_SKSEED] = {0};
    randombytes( sk_seed , LEN_SKSEED );

#if defined _RAINBOW_CLASSIC

    generate_keypair( (pk_t*) pk , (sk_t*) sk , sk_seed );

#elif defined _RAINBOW_CYCLIC

    unsigned char pk_seed[LEN_PKSEED] = {0};
    randombytes( pk_seed , LEN_PKSEED );
    generate_keypair_cyclic( (cpk_t*) pk , (sk_t*) sk , pk_seed , sk_seed );

#elif defined _RAINBOW_CYCLIC_COMPRESSED

    unsigned char pk_seed[LEN_PKSEED] = {0};
    randombytes( pk_seed , LEN_PKSEED );
    generate_compact_keypair_cyclic( (cpk_t*) pk , (csk_t*) sk , pk_seed , sk_seed );

#else
error here
#endif
    return 0;
}





int
crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk)
{
	unsigned char digest[_HASH_LEN];

	hash_msg( digest , _HASH_LEN , m , mlen );

	memcpy( sm , m , mlen );
	smlen[0] = mlen + _SIGNATURE_BYTE;

#if defined _RAINBOW_CLASSIC

	return rainbow_sign( sm + mlen , (const sk_t*)sk , digest );

#elif defined _RAINBOW_CYCLIC

	return rainbow_sign( sm + mlen , (const sk_t*)sk , digest );

#elif defined _RAINBOW_CYCLIC_COMPRESSED

	return rainbow_sign_cyclic( sm + mlen , (const csk_t*)sk , digest );

#else
error here
#endif


}






int
crypto_sign_open(unsigned char *m, unsigned long long *mlen,const unsigned char *sm, unsigned long long smlen,const unsigned char *pk)
{
	if( _SIGNATURE_BYTE > smlen ) return -1;
	memcpy( m , sm , smlen-_SIGNATURE_BYTE );
	mlen[0] = smlen-_SIGNATURE_BYTE;

	unsigned char digest[_HASH_LEN];
	hash_msg( digest , _HASH_LEN , m , *mlen );

#if defined _RAINBOW_CLASSIC

	return rainbow_verify( digest , sm + mlen[0] , (const pk_t *)pk );

#elif defined _RAINBOW_CYCLIC

	return rainbow_verify_cyclic( digest , sm + mlen[0] , (const cpk_t *)pk );

#elif defined _RAINBOW_CYCLIC_COMPRESSED

	return rainbow_verify_cyclic( digest , sm + mlen[0] , (const cpk_t *)pk );

#else
error here
#endif


}


int crypto_sign_ring(const unsigned char **pk, unsigned char **vector, unsigned char *m, unsigned long long mlen, const unsigned char *sk, const int users) {

	// if( _SIGNATURE_BYTE > smlen ) return -1;
	// memcpy( m , sm , smlen-_SIGNATURE_BYTE );
	// mlen[0] = smlen-_SIGNATURE_BYTE;

	unsigned char digest[_HASH_LEN];
	unsigned char correct[_PUB_M_BYTE];
	hash_msg( digest , _HASH_LEN , m , mlen);
	// unsigned char digest_salt[_HASH_LEN + _SALT_BYTE];
    // memcpy( digest_salt , digest , _HASH_LEN );
	// TODO : why we need compute salt ?? check in signature generation
    // memcpy( digest_salt+_HASH_LEN , vector[0] +_PUB_N_BYTE , _SALT_BYTE );
    // hash_msg( correct , _PUB_M_BYTE , digest_salt , _HASH_LEN+_SALT_BYTE );
	
	unsigned char digest_ck[_PUB_M_BYTE];
	unsigned char w_with_vawe[_PUB_M_BYTE];
	unsigned char result[_PUB_M_BYTE];
	for (int i = 0; i< _PUB_M_BYTE;i++){
		result[i] = 0;
	}
	//we need to supply for different public keys
	for (int h = 1; h < users; h++){
		rainbow_sign_ring( result , vector[h] , (const pk_t *)pk[h], digest_ck);
		// for (int i = 0; i< _PUB_M_BYTE;i++){
		// 	printf("%d ", result[i]);
		// }
	}

	// rainbow_sign_ring( result , vector[0] , (const pk_t *)pk[1], digest_ck);

	// printf("W with vawe: \n");
	for (int i = 0; i < _PUB_M_BYTE ;i++){
		w_with_vawe[i] = digest[i] - result[i];
		// printf("%d ", w_with_vawe[i]);
	}
	// printf("\n");
	unsigned char * signature = malloc( CRYPTO_BYTES + _PUB_M_BYTE );
	// printf("%ld \n", sizeof(signature)/sizeof(signature[0]));

	// memcpy( signature , m , mlen );


	unsigned char experiment[_PUB_M_BYTE];
	// int x = rainbow_sign(signature,(const sk_t*)sk, w_with_vawe);
	unsigned long long smlen = 0;
	unsigned long long w_len = _PUB_M_BYTE;
	int y = crypto_sign( signature, &smlen, w_with_vawe , w_len , sk);
	// int x = crypto_sign_open( w_with_vawe , &w_len , signature , w_len + CRYPTO_BYTES , pk );
	// printf("%d ", x);
	// printf("Signature: \n");
	// printf("%ld \n", sizeof(signature)/sizeof(signature[0]));
	// printf("%ld \n", sizeof(vector[0])/sizeof(vector[0][0]));
	// printf("%d \n", x);

	// printf("%ld \n", mlen + CRYPTO_BYTES);	

	// for (int i = 0; i < _PUB_M_BYTE; i++){
	// 	printf("%d ", signature[i]);
	// }

	// printf("Correct signature: \n");
	for (int i = 0; i < CRYPTO_BYTES + _PUB_M_BYTE ;i++){
		vector[0][i] = signature[i];
		// printf("%d ", vector[1][i]);
	}

	return 0;

	// return rainbow_verify_ring(pk, vector, m, &mlen, mlen + CRYPTO_BYTES);
}

int rainbow_verify_ring(const unsigned char **pk, const unsigned char **signature, unsigned char *m, unsigned long long *mlen, unsigned long long smlen, const int users) {
	// if( _SIGNATURE_BYTE > smlen ) return -1;
	// memcpy( m , signature[0] , smlen-_SIGNATURE_BYTE );
	// mlen[0] = smlen-_SIGNATURE_BYTE;

	unsigned char digest[_HASH_LEN];
	hash_msg( digest , _HASH_LEN , m , *mlen );
	unsigned char digest_ck[_PUB_M_BYTE];
	unsigned char digest_ck1[_PUB_M_BYTE];
	unsigned char result[_PUB_M_BYTE];
	unsigned long long w_len = _PUB_M_BYTE;
	unsigned long long smlen1 = w_len + CRYPTO_BYTES;

	// unsigned char result[_PUB_M_BYTE];
	for (int i = 0; i< _PUB_M_BYTE;i++){
		result[i] = 0;
	}

	int j;
	for (j = 1; j < users; j ++){
		rainbow_sign_ring( result , signature[j] , (const pk_t *)pk[j], digest_ck);
	}
 
	printf("Digest_ck: \n");
	for (int i = 0; i < _PUB_M_BYTE ;i++){
		printf("%d ", signature[1][i]);
	}

	// for (int i = 0; i < _PUB_M_BYTE; i++){
	// 	result[i] = digest_ck[i] + digest_ck1[i];
	// 	printf("%d ", result[i]);
	// }
	printf("\n");

	unsigned char w_with_vawe[_PUB_M_BYTE];
	printf("W with vawe: \n");
	for (int i = 0; i < _PUB_M_BYTE ;i++){
		w_with_vawe[i] = digest[i] - result[i];
		printf("%d ", w_with_vawe[i]);
	}
	
	memcpy( w_with_vawe , signature[0] , smlen1-_SIGNATURE_BYTE );
	// &w_len[0] = smlen1-_SIGNATURE_BYTE;

	unsigned char digest_w[_HASH_LEN];
	hash_msg( digest_w , _HASH_LEN , w_with_vawe , w_len);

	rainbow_sign_ring( result , signature[0] + w_len, (const pk_t *)pk[0], digest_ck1);

	unsigned char correct[_PUB_M_BYTE];
    unsigned char digest_salt[_HASH_LEN + _SALT_BYTE];
    memcpy( digest_salt , digest_w , _HASH_LEN );
    memcpy( digest_salt+_HASH_LEN , signature[0] + w_len +_PUB_N_BYTE , _SALT_BYTE );
    hash_msg( correct , _PUB_M_BYTE , digest_salt , _HASH_LEN+_SALT_BYTE );  // H( digest || salt )

	printf("Correct: \n");
	for(unsigned i=0;i<_PUB_M_BYTE;i++) {
		printf("%d ", correct[i]);
    }

	printf("\n");

	printf("Consistency: \n");
    // check consistancy.
    unsigned char cc = 0;
    for(unsigned i=0;i<_PUB_M_BYTE;i++) {
		printf("%d ", digest_ck1[i]);
        cc |= (correct[i]^digest_ck1[i]);
    }
    return (0==cc)? 0: -1;

}

