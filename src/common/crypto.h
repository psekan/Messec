#ifndef MESSEC_CRYPTO_H
#define MESSEC_CRYPTO_H

#include <mbedtls/entropy_poll.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <QtCore/qlist.h>

enum MessageTypes;
void initRandomContexts(mbedtls_entropy_context& entropy, mbedtls_ctr_drbg_context& ctr_drbg);
int generateRandomNumber(unsigned char* output, int output_len);
const unsigned char* encryptMessage(quint8 messageType, uint32_t* coutner, const unsigned char* input, size_t inputLength, size_t* outputLength, unsigned char* tag, const unsigned char* key);
const unsigned char* decryptMessage(quint8* messageType, uint32_t* counter, const unsigned char* input, size_t inputLength, size_t* outputLength, unsigned char* tag, const unsigned char* key);
#endif //MESSEC_CRYPTO_H