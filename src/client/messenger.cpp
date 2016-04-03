//
// Created by Peter on 12.03.2016.
//

#include "messenger.h"
#include <mbedtls/gcm.h>
#include <string.h>
#include <limits.h>

union charInt
{
	uint32_t uint;
	unsigned char string[4];
};

const int size_of_counter = sizeof(uint32_t) / sizeof(unsigned char);
const int size_of_tag = 16 / sizeof(unsigned char); // tag je vzdy 16 bytov

void intToUCHar(uint32_t input, unsigned char* output)
{
	memcpy(output, &input, 4);
}

void uCHarToInt(unsigned char* input, uint32_t* output)
{
	memcpy(output, input, 4);
}

void Messenger::setAes(unsigned char aesKey[32], unsigned char aesIv[32]) {
	memcpy(this->m_aesKey, aesKey, sizeof(unsigned char) * 32);
	memcpy(this->m_aesIv, aesIv, sizeof(unsigned char) * 32);
}

Messenger::Messenger(std::string userName, unsigned int socket, unsigned char aesKey[32], unsigned char aesIv[32], uint32_t inCounter,
	uint32_t outCounter)
	: m_userName(userName), m_socket(socket), m_inCounter(inCounter), m_outCounter(outCounter) {
	this->setAes(aesKey, aesIv);
	m_isAlive = true;
}

void Messenger::setCallbacks(std::function<void(Messenger&, ConnectionErrors)> connectionLostCallback, std::function<void(Messenger&)> communicationEndedCallback, std::function<void(Messenger&, unsigned char, unsigned long long, unsigned char*)> newMessageCallback) {
	this->m_communicationEndedCallback = communicationEndedCallback;
	this->m_connectionLostCallback = connectionLostCallback;
	this->m_newMessageCallback = newMessageCallback;
}

bool Messenger::isAlive() const {
	return m_isAlive;
}

void Messenger::exitCommunication() {
	m_isAlive = false;
}

// sprava = counter_tag[16] + counter[4] + message_tag[16] + message[messageLength - 36]
bool Messenger::receiveMessage(unsigned char& messageType, unsigned long long& messageLength, unsigned char* message, unsigned char* decrypted_message)
{
	unsigned char* counter = message + size_of_tag;
	unsigned char* message_tag = message + size_of_counter + size_of_tag;
	unsigned char decrypted_counter[12];

	bool result = decrypt(counter, size_of_counter, decrypted_counter, m_aesIv, size_of_tag, message_tag, m_aesKey);

	union charInt counter_union;
	memcpy(counter_union.string, decrypted_counter, 4);

	if (result)
	{
		++m_inCounter;
		if (counter_union.uint == m_inCounter)
		{
			return decrypt(message, messageLength, decrypted_message, m_aesIv, size_of_tag, message_tag, m_aesKey);
		}
		--m_outCounter;
	}
	return result;
}

bool Messenger::sendMessage(unsigned char messageType, unsigned long long messageLength, unsigned char* message, unsigned char* encrypted_message)
{
	unsigned char* counter = message + size_of_tag;
	unsigned char* message_tag = message + size_of_counter + size_of_tag;

	bool result = encrypt(message, messageLength, message_tag + size_of_tag, m_aesIv, size_of_tag, message_tag, m_aesKey);

	++m_outCounter;

	union charInt counter_union;
	counter_union.uint = m_outCounter;

	if (result)
	{
		result = encrypt(counter_union.string, size_of_counter, counter, m_aesIv, size_of_tag, encrypted_message, m_aesKey);
		return result;
	}
	--m_outCounter;
	return false;
}

bool Messenger::encrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, /*m_aesKey*/ key, 256);
	return !mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, inlen, iv, iv_len, nullptr, 0, input, output, 16, tag);
}

bool Messenger::decrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, /*m_aesKey*/ key, 256);
	return !mbedtls_gcm_auth_decrypt(&ctx, inlen, iv, iv_len, nullptr, 0, tag, 16, input, output);
}

