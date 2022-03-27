#include <stdio.h> 

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

#define ECCTYPE    "prime256v1"
 
void SignAndVerifyTest()
{
    SHA256_CTX      c;
    EC_KEY          *ecKey = NULL;
    int             nidEcc;
    unsigned char   m[SHA256_DIGEST_LENGTH];
    unsigned char   sig[256];                   // Must greater than ECDSA_size(ecKey)
    unsigned int    lenSig;
    int             iRet;
    int             i;
    ECDSA_SIG* ecSig = NULL;
    const unsigned char* sigptr;

    EC_KEY          *ecKey2 = NULL;
	const EC_POINT*	pub_key_point;
 
 
    // Generate Hash for signing
    SHA256_Init(&c);
    SHA256_Update(&c, "This is Data for Signing.", 25);
    SHA256_Final(m, &c);
    OPENSSL_cleanse(&c, sizeof(c));
 
    // Set Key Type.
    nidEcc = OBJ_txt2nid( ECCTYPE );
    ecKey = EC_KEY_new_by_curve_name(nidEcc);
    ecKey2 = EC_KEY_new_by_curve_name(nidEcc);
    if (ecKey == NULL)  ERR_print_errors_fp(stderr);
    if (ecKey2 == NULL)  ERR_print_errors_fp(stderr);

    EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);
    EC_KEY_set_asn1_flag(ecKey2, OPENSSL_EC_NAMED_CURVE);

    // Generate Key.
    EC_KEY_generate_key(ecKey);
 
	pub_key_point = EC_KEY_get0_public_key(ecKey);
    printf("LINE %d : %s\n", __LINE__, EC_KEY_set_public_key( ecKey2, pub_key_point ) ? "SUCCESS":"FAIL");

    // Sign Message Digest.
    ECDSA_sign(0, m, SHA256_DIGEST_LENGTH, sig, &lenSig, ecKey);
    for(i=0; i<lenSig; i++ )
        printf( "%02X ", sig[i] );

    printf("\nLEN=%d \n", lenSig );


    sigptr = &sig[0];
    if( d2i_ECDSA_SIG(&ecSig, &sigptr, lenSig) == NULL ) {
        printf("Error\n");
        return ;
    }

    iRet = ECDSA_verify(0, m, SHA256_DIGEST_LENGTH, sig, lenSig, ecKey);
    printf("Verify Result is %d %d\n", iRet, lenSig);

    iRet = ECDSA_verify(0, m, SHA256_DIGEST_LENGTH, sig, lenSig, ecKey2);
    printf("Verify Result is %d %d\n", iRet, lenSig);
 
    EC_KEY_free(ecKey);
    EC_KEY_free(ecKey2);
}
 
 
int main()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
 
    SignAndVerifyTest();
 
    ERR_print_errors_fp(stderr);
 
    return 0;
}
