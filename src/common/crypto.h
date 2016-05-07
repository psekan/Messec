#ifndef MESSEC_CRYPTO_H
#define MESSEC_CRYPTO_H

#include <QTcpSocket>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

void initRandomContexts(mbedtls_entropy_context& entropy, mbedtls_ctr_drbg_context& ctr_drbg);
int generateRandomNumber(unsigned char* output, int output_len);
const unsigned char* encryptMessage(quint8 messageType, uint32_t* counter, const unsigned char* input, uint32_t inputLength, size_t& outputLength, unsigned char* tag, const unsigned char* key);
const unsigned char* decryptMessage(quint8* messageType, uint32_t* counter, const unsigned char* input, uint32_t inputLength, unsigned char* tag, const unsigned char* key);
void parseMessage(QTcpSocket* socket, uint32_t* m_inCounter, quint8* message_type, QString* message, unsigned char* m_aesKey);
bool sendMessage(QTcpSocket* socket, uint32_t* m_outCounter, quint8 messageType, QString message, unsigned char* m_aesKey);
bool parseMessage(QByteArray& input, uint32_t* m_inCounter, quint8* message_type, QByteArray& message, unsigned char* m_aesKey);
bool sendMessage(QTcpSocket* socket, uint32_t* m_outCounter, quint8 messageType, QByteArray& message, unsigned char* m_aesKey);
bool encrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key);
bool decrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, const unsigned char* tag, const unsigned char* key);
bool decryptLength(uint32_t& lenght, unsigned char* input, unsigned char *tag, uint32_t* counter, unsigned char* m_aesKey);
bool encryptLength(uint32_t lenght, unsigned char* output, unsigned char *tag, uint32_t* counter, unsigned char* m_aesKey);

#endif //MESSEC_CRYPTO_H