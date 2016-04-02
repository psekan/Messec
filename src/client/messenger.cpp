//
// Created by Peter on 12.03.2016.
//

#include "messenger.h"
#include <mbedtls/gcm.h>
#include <string.h>
#include <limits.h>

// za predpokladu ze mame max 32 bitovu hodnotu v tom pocitadle (nezavisle od velkosti unsigned intu) 
const int size_of_counter = 32 / sizeof(unsigned char);

void intToUCHar(unsigned int input, unsigned char* oputput)
{
	// keby je unsigned int 64 bitov tak by sa skopirovali len same nuly preto sa to posuva (mempcy skopiruje prve 4 bity)
	// neni to prenositelne na ine endiany ani na platformu kde je int len 16 bitov
	if (sizeof(unsigned int) == 8) {
		input <<= 32;
	}

	memcpy(oputput, reinterpret_cast<char*>(&input), 4);
}

void uCHarToInt(unsigned char* input, unsigned int* oputput)
{
	memcpy(oputput, reinterpret_cast<unsigned int*>(&input), 4);

	if (sizeof(unsigned int) == 8) {
		*oputput >>= 32;
	}
}

void Messenger::setAes(unsigned char aesKey[32], unsigned char aesIv[32]) {
	memcpy(this->m_aesKey, aesKey, sizeof(unsigned char) * 32);
	memcpy(this->m_aesIv, aesIv, sizeof(unsigned char) * 32);
}

Messenger::Messenger(std::string userName, unsigned int socket, unsigned char aesKey[32], unsigned char aesIv[32], unsigned int inCounter, 
	unsigned int outCounter)
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

// sprava = counter_tag[16] + counter[size_of_counter] + message_tag[16] + message[messageLength - 64]
unsigned char* Messenger::receiveMessage(unsigned char& messageType, unsigned long long& messageLength, unsigned char* message)
{
	unsigned char* counter = message + 16;
	unsigned char* message_tag = message + size_of_counter + 16;

	unsigned char* decrypted_message = static_cast<unsigned char*>(malloc(messageLength - 16 - 16 - size_of_counter + 8));
	unsigned char decrypted_counter[40];

	bool result = decrypt(counter, size_of_counter, decrypted_counter, m_aesIv, 16, message_tag, m_aesKey);

	unsigned int counter_int;

	if (result)
	{
		uCHarToInt(decrypted_counter, &counter_int);
		++m_inCounter;

		if(m_inCounter > UINT32_MAX)
		{
			m_inCounter = 0;
		}

		if (counter_int != m_inCounter)
		{
			result = decrypt(message, messageLength, decrypted_message, m_aesIv, 16, message_tag, m_aesKey);

			if (result)
			{
				return decrypted_message;
			}
			return nullptr;
		}
	}
	return nullptr;
}

bool Messenger::sendMessage(unsigned char messageType, unsigned long long messageLength, unsigned char* message) {

	unsigned char* whole_message = static_cast<unsigned char*>(malloc(messageLength + 16 + 16 + size_of_counter));
	
	unsigned char* counter = message + 16;
	unsigned char* message_tag = message + size_of_counter + 16;

	bool result = encrypt(message, messageLength, message_tag + 16, m_aesIv, 16, message_tag, m_aesKey);

	unsigned char counter_char[size_of_counter];

	++m_outCounter;

	if (m_inCounter > UINT32_MAX)
	{
		m_inCounter = 0;
	}

	intToUCHar(m_outCounter, counter_char);

	if (result)
	{
		result = encrypt(counter_char, size_of_counter, counter, m_aesIv, 16, whole_message, m_aesKey);
		return result;
	}
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

