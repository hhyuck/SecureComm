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
 
 
    // Generate Hash for signing
    SHA256_Init(&c);
    SHA256_Update(&c, "This is Data for Signing.", 25);
    SHA256_Final(m, &c);
    OPENSSL_cleanse(&c, sizeof(c));
 
    // Set Key Type.
    nidEcc = OBJ_txt2nid( ECCTYPE );
    ecKey = EC_KEY_new_by_curve_name(nidEcc);
    if (ecKey == NULL)  ERR_print_errors_fp(stderr);
 
    // Generate Key.
    EC_KEY_generate_key(ecKey);
 
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
 
    // Change Message Digest.
    m[0]++;
    iRet = ECDSA_verify(0, m, SHA256_DIGEST_LENGTH, sig, lenSig, ecKey);
    printf("After Fake  : Verify Result is %d \n", iRet);
    puts("\n------------------------------\n");
 
    EC_KEY_free(ecKey);
}
 
 
int main()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
 
    SignAndVerifyTest();
 
    ERR_print_errors_fp(stderr);
 
    return 0;
}
