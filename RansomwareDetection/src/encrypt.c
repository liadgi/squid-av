#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <arpa/inet.h> /* For htonl() */



int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
	unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
	unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int ciphertext_len;

	int len;


	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) { printf("if(!(ctx = EVP_CIPHER_CTX_new()))"); return;}//handleErrors();

	/* Initialise the envelope seal operation. This operation generates
	 * a key for the provided cipher, and then encrypts that key a number
	 * of times (one for each public key provided in the pub_key array). In
	 * this example the array size is just one. This operation also
	 * generates an IV and places it in iv. */
	if(1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, pub_key, 1))
		printf("if(1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key,"); return;
		//handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_SealUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		printf("if(1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))"); return;
		//handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_SealFinal(ctx, ciphertext + len, &len)) printf("if(1 != EVP_SealFinal(ctx, ciphertext + len, &len))"); return;//handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}
