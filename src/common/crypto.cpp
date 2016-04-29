#include "crypto.h"
#include <cstring>
#include <mbedtls/gcm.h>


bool encrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
	return !mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, inlen, iv, iv_len, nullptr, 0, input, output, 16, tag);
}

void initRandomContexts(mbedtls_entropy_context& entropy, mbedtls_ctr_drbg_context& ctr_drbg)
{
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_add_source(&entropy, mbedtls_platform_entropy_poll, nullptr, 64, MBEDTLS_ENTROPY_SOURCE_STRONG);
	mbedtls_entropy_add_source(&entropy, mbedtls_hardclock_poll, nullptr, 16, MBEDTLS_ENTROPY_SOURCE_WEAK);
}

int generateRandomNumber(unsigned char* output, int output_len)
{
	int result = 0;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *personalization = "nahodne_slova_na_zvysenie_entropie_toto_nie_je_seed_generacia_nahodneho cisla";
	initRandomContexts(entropy, ctr_drbg);

	result += mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		reinterpret_cast<const unsigned char *>(personalization), strlen(personalization));

	result += mbedtls_ctr_drbg_random(&ctr_drbg, output, output_len);

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return result;
}

const unsigned char* encryptMessage(quint8 messageType, uint32_t* counter, const unsigned char* input, size_t inputLength, size_t* outputLength, unsigned char* tag, const unsigned char* key)
{
	(*counter)++;
	unsigned char uCounter[4];
	unsigned char output[64];
	unsigned char IV[16];
	size_t sizeOfMessageType = sizeof(messageType);
	*outputLength = inputLength + sizeOfMessageType;
    unsigned char* preparedMessageBuffer = new unsigned char[*outputLength];
	unsigned char* encryptedMessage = new unsigned char[*outputLength];
	
	memcpy(uCounter, counter, 4);
	mbedtls_sha512(uCounter, 4, output, 0);

	memcpy(output, IV, 16);
	memcpy(preparedMessageBuffer, &messageType, sizeOfMessageType);
	memcpy(preparedMessageBuffer + sizeOfMessageType, input, inputLength);

	if(encrypt(preparedMessageBuffer, *outputLength, encryptedMessage, IV, 16, tag, key))
	{
		delete[] preparedMessageBuffer;
		return encryptedMessage;
	}
	(*counter)--;
	delete[] preparedMessageBuffer;
	delete[] encryptedMessage;
	return nullptr;
}

