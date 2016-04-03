//
// Created by Peter on 12.03.2016.
//

#include "messenger.h"
#include <mbedtls/gcm.h>
#include <string.h>
#include <limits.h>

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

bool Messenger::sendMessage(unsigned char messageType, unsigned long long messageLength, const unsigned char* message) {
	unsigned char* preparedMessageBuffer = new unsigned char[messageLength + 21];
	if (!prepareMessageToSend(messageType, messageLength, message, preparedMessageBuffer)) {
		delete[] preparedMessageBuffer;
		return false;
	}
	//TODO send message by network
	delete[] preparedMessageBuffer;
	return false;
}

bool Messenger::prepareMessageToSend(unsigned char messageType, unsigned long long messageLength, const unsigned char* message, unsigned char* preparedMessage) {
	size_t sizeOfMessageType = 1;
	size_t sizeOfCounter = 4;

	//Format of input = counter, messageType, message
	size_t inputLength = sizeOfCounter + sizeOfMessageType + messageLength;
	unsigned char* input = new unsigned char[inputLength + 8]; //+8 needed in function encrypt
	memcpy(input, &m_outCounter, sizeOfCounter);
	memcpy(input + sizeOfCounter, &messageType, sizeOfMessageType);
	memcpy(input + sizeOfCounter + sizeOfMessageType, message, messageLength);

	//Increase out counter
	++m_outCounter;

	//Compute tag and encrypted output
	unsigned char* output = new unsigned char[inputLength + 8]; //+8 needed in function encrypt
	unsigned char* tag = new unsigned char[TAG_SIZE];
	if (!encrypt(input, inputLength, output, m_aesIv, 32, tag, m_aesKey)) {
		delete[] input;
		delete[] output;
		delete[] tag;
		return false;
	}
	
	//Copy tag and output to prepared message
	memcpy(preparedMessage, tag, TAG_SIZE);
	memcpy(preparedMessage + TAG_SIZE, output, inputLength);

	//Free allocated memory
	delete[] input;
	delete[] output;
	delete[] tag;
	return true;	
	
	/*unsigned char* counter = message + size_of_tag;
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
	return false;*/
}

bool Messenger::parseReceivedMessage(const unsigned char* receivedMessage, unsigned long long receivedMessageLength, unsigned char& messageType, unsigned char* message) {
	size_t sizeOfMessageType = 1;
	size_t sizeOfCounter = 4;

	//Split received message to tag and encrypted message
	size_t encryptedMessageLength = receivedMessageLength - TAG_SIZE;
	unsigned char* encryptedMessage = new unsigned char[encryptedMessageLength];
	unsigned char* tag = new unsigned char[TAG_SIZE];
	memcpy(tag, receivedMessage, TAG_SIZE);
	memcpy(encryptedMessage, receivedMessage + TAG_SIZE, encryptedMessageLength);

	//Decrypt messsage
	unsigned char* decryptedMessage = new unsigned char[encryptedMessageLength];
	if (!decrypt(encryptedMessage, encryptedMessageLength, decryptedMessage, m_aesIv, 32, tag, m_aesKey)) {
		delete[] encryptedMessage;
		delete[] tag;
		delete[] decryptedMessage;
		return false;
	}

	//Parse decrypted message
	size_t messageLength = encryptedMessageLength - sizeOfMessageType - sizeOfCounter;
	uint32_t counterInMessage = 0;
	memcpy(&counterInMessage, decryptedMessage, sizeOfCounter);
	memcpy(&messageType, decryptedMessage + sizeOfCounter, sizeOfMessageType);
	memcpy(message, decryptedMessage + sizeOfCounter + sizeOfMessageType, messageLength);

	//Free allocated memory
	delete[] encryptedMessage;
	delete[] tag;
	delete[] decryptedMessage;

	//Check if counter is correct
	if (counterInMessage != m_inCounter) {
		return false;
	}

	//Increase out counter
	++m_inCounter;

	return true;
	
	/*unsigned char* counter = message + size_of_tag;
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
	return result;*/
}

bool Messenger::encrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, /*m_aesKey*/ key, 256);
	return !mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, inlen, iv, iv_len, nullptr, 0, input, output, TAG_SIZE, tag);
}

bool Messenger::decrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, /*m_aesKey*/ key, 256);
	return !mbedtls_gcm_auth_decrypt(&ctx, inlen, iv, iv_len, nullptr, 0, tag, TAG_SIZE, input, output);
}

