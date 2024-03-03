#include <gmp.h>

void RSA_Encrypt(unsigned char* plaintext, unsigned char* rsaPublicKey, unsigned int exponent)
{
	mpz_t _output, _input, _exponent, _rsaPublicKey;

	mpz_init(_output);
	mpz_init(_input);
	mpz_import(_input, 128, 1, 1, 0, 0, plaintext);
	mpz_init_set_ui(_exponent, exponent);	//e
	mpz_init(_rsaPublicKey);	//n
	mpz_import(_rsaPublicKey, 128, 1, 1, 0, 0, rsaPublicKey);
	
	mpz_powm(_output, _input, _exponent, _rsaPublicKey);
	mpz_export(plaintext, NULL, 1, 1, 0, 0, _output);
	
	mpz_clears(_output, _input, _rsaPublicKey, _exponent, NULL);
}