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


int crypto_sign_ring(const unsigned char *pk, unsigned char **vector, unsigned char *m, unsigned long long mlen) {

	// if( _SIGNATURE_BYTE > smlen ) return -1;
	// memcpy( m , sm , smlen-_SIGNATURE_BYTE );
	// mlen[0] = smlen-_SIGNATURE_BYTE;

	unsigned char digest[_HASH_LEN];
	unsigned char correct[_PUB_M_BYTE];
	hash_msg( digest , _HASH_LEN , m , mlen);
	unsigned char digest_salt[_HASH_LEN + _SALT_BYTE];
    memcpy( digest_salt , digest , _HASH_LEN );
	// TODO : why we need compute salt ?? check in signature generation
    memcpy( digest_salt+_HASH_LEN , vector[0] +_PUB_N_BYTE , _SALT_BYTE );
    hash_msg( correct , _PUB_M_BYTE , digest_salt , _HASH_LEN+_SALT_BYTE );
	
	unsigned char digest_ck[_PUB_M_BYTE];
	unsigned char w_with_vawe[_PUB_M_BYTE];
	//we need to supply for different public keys
	for (int i = 0; i < 2; i++){
		 rainbow_sign_ring( digest , vector[i] , (const pk_t *)pk, digest_ck);
    }

	printf("W with vawe: \n");
	for (int i = 0; i < _PUB_M_BYTE ;i++){
		w_with_vawe[i] = correct[i] - digest_ck[i];
		printf("%d ", w_with_vawe[i]);
	}
	printf("\n");

	return 0;
}

