#include "crypto.h"
#include <cstring>
#include <mbedtls/gcm.h>
#include <iostream>
#include <QtCore/QDataStream>
#include <mbedtls/entropy_poll.h>
#include <QtCore/qlist.h>
#include "messageTypes.h"


bool encrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
	return !mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, inlen, iv, iv_len, nullptr, 0, input, output, 16, tag);
}

bool decrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, const unsigned char* tag, const unsigned char* key)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
	return !mbedtls_gcm_auth_decrypt(&ctx, inlen, iv, iv_len, nullptr, 0, tag, 16, input, output);
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

const unsigned char* encryptMessage(quint8 messageType, uint32_t* counter, const unsigned char* input, uint32_t inputLength, size_t& outputLength, unsigned char* tag, const unsigned char* key)
{
	(*counter)++;
	unsigned char output[64];
	uint32_t sizeOfMessageType = sizeof(quint8);
	outputLength = inputLength + sizeOfMessageType;
    unsigned char* preparedMessageBuffer = new unsigned char[outputLength];
	unsigned char* encryptedMessage = new unsigned char[outputLength];
	
	mbedtls_sha512(reinterpret_cast<unsigned char*>(counter), 4, output, 0);

	memcpy(preparedMessageBuffer, &messageType, sizeOfMessageType);
	memcpy(preparedMessageBuffer + sizeOfMessageType, input, inputLength);

	if(encrypt(preparedMessageBuffer, outputLength, encryptedMessage, output, 16, tag, key))
	{
		delete[] preparedMessageBuffer;
		return encryptedMessage;
	}
	(*counter)--;
	delete[] preparedMessageBuffer;
	delete[] encryptedMessage;
	return nullptr;
}

const unsigned char* decryptMessage(quint8* messageType, uint32_t* counter, const unsigned char* input, uint32_t inputLength, unsigned char* tag, const unsigned char* key)
{
	(*counter)++;
	unsigned char output[64];
	uint32_t sizeOfMessageType = sizeof(quint8);
	unsigned char* decryptedMessage = new unsigned char[inputLength + 8];

	mbedtls_sha512(reinterpret_cast<unsigned char*>(counter), 4, output, 0);

	if(decrypt(input, inputLength, decryptedMessage, output, 16, tag, key))
	{
		memcpy(messageType, decryptedMessage, sizeOfMessageType);
		return decryptedMessage + sizeOfMessageType;
	}
	(*counter)--;
	delete[] decryptedMessage;
	return nullptr;
}

bool sendMessage(QTcpSocket* socket, uint32_t* m_outCounter, quint8 messageType, QString message, unsigned char* m_aesKey) 
{
	QByteArray array;
	QDataStream output(&array, QIODevice::WriteOnly);

	uint32_t length;
	unsigned char tag[16];
	
	(*m_outCounter)++;  // we can parse message in right order easier, message counter should be one more than lenght
	const unsigned char* uMessage = encryptMessage(messageType, m_outCounter, reinterpret_cast<const unsigned char*>(message.toStdString().c_str()), message.length(), length, tag, m_aesKey);
	(*m_outCounter) -= 2;
	unsigned char encryptedLengthAndTag[20];
	bool result = encryptLength(length, encryptedLengthAndTag, encryptedLengthAndTag + 4, m_outCounter, m_aesKey);
	(*m_outCounter) ++;

	if (uMessage == nullptr || !result)
	{
		std::cout << "encryption failed" << std::endl;
		return false;
	}

	output.writeRawData(reinterpret_cast<const char*>(encryptedLengthAndTag), 20);
	output.writeRawData(reinterpret_cast<const char*>(tag), 16);
	output.writeRawData(reinterpret_cast<const char*>(uMessage), length);
	socket->write(array);
	socket->waitForBytesWritten();
	delete[] uMessage;

	return true;
}

void parseMessage(QTcpSocket* socket, uint32_t* m_inCounter, quint8* message_type, QString* message, unsigned char* m_aesKey)
{
	QDataStream u(socket);
	unsigned char tag[16];
	unsigned char encryptedLengthAndTag[20];
	uint32_t messageLength;
	
	u.readRawData(reinterpret_cast<char*>(encryptedLengthAndTag), 20);
	
	bool result = decryptLength(messageLength, encryptedLengthAndTag, encryptedLengthAndTag + 4, m_inCounter, m_aesKey);
	unsigned char *uMessage = new unsigned char[messageLength];
	
	u.readRawData(reinterpret_cast<char*>(tag), 16);
	u.readRawData(reinterpret_cast<char*>(uMessage), messageLength);

	const unsigned char* pMessage = decryptMessage(message_type, m_inCounter, uMessage, messageLength, tag, m_aesKey);
	if (pMessage == nullptr || !result)
	{
		std::cout << "decryption fail" << std::endl;
		delete[] uMessage;
		return;
	}
	std::string messageString = std::string(reinterpret_cast<const char *>(pMessage), messageLength - sizeof(quint8));
	*message = QString::fromStdString(messageString);
	delete[] uMessage;
	delete[] (pMessage - sizeof(quint8));
}


bool parseMessage(QByteArray &input, uint32_t* m_inCounter, quint8* message_type, QByteArray& message, unsigned char* m_aesKey)
{
	unsigned char tag[16];
	size_t messageLength = input.size() - 16;
	QDataStream socket(&input, QIODevice::ReadOnly);
	unsigned char *uMessage = new unsigned char[messageLength];
	socket.readRawData(reinterpret_cast<char*>(tag), 16);
	socket.readRawData(reinterpret_cast<char*>(uMessage), messageLength);
	

	const unsigned char* pMessage = decryptMessage(message_type, m_inCounter, uMessage, messageLength, tag, m_aesKey);
	if (pMessage == nullptr)
	{
		delete[] uMessage;
		return false;
	}
	message.append(reinterpret_cast<const char *>(pMessage), messageLength - sizeof(quint8));
	delete[] uMessage;
	delete[](pMessage - sizeof(quint8));
	return true;
}

bool sendMessage(QTcpSocket* socket, uint32_t* m_outCounter, quint8 messageType, QByteArray& message, unsigned char* m_aesKey)
{
	size_t length;
	unsigned char tag[16];
	
	(*m_outCounter)++;  // we can parse message in right order easier, message counter should be one more than lenght
	const unsigned char* uMessage = encryptMessage(messageType, m_outCounter, reinterpret_cast<const unsigned char*>(message.data()), message.size(), length, tag, m_aesKey);
	(*m_outCounter) -= 2;
	unsigned char encryptedLengthAndTag[20];
	bool result = encryptLength(length, encryptedLengthAndTag, encryptedLengthAndTag + 4, m_outCounter, m_aesKey);
	(*m_outCounter)++;

	if (uMessage == nullptr || !result)
	{
		std::cout << "encryption failed" << std::endl;
		delete[] uMessage;
		return false;
	}

	socket->write(reinterpret_cast<const char*>(encryptedLengthAndTag), 20);
	socket->write(reinterpret_cast<const char*>(tag), 16);
	socket->write(reinterpret_cast<const char*>(uMessage), length);
	

	socket->waitForBytesWritten();
	delete[] uMessage;

	return true;
}

bool encryptLength(uint32_t lenght, unsigned char* output, unsigned char *tag, uint32_t* counter, unsigned char* m_aesKey)
{
	(*counter)++;
	unsigned char shaOutput[64];
	
	mbedtls_sha512(reinterpret_cast<unsigned char*>(counter), 4, shaOutput, 0);

	if(encrypt(reinterpret_cast<unsigned char*>(&lenght), 4, output, shaOutput, 16, tag, m_aesKey))
	{
		return true;
	}
	(*counter)--;
	return false;
}

bool decryptLength(uint32_t& lenght, unsigned char* input, unsigned char *tag, uint32_t* counter, unsigned char* m_aesKey)
{
	(*counter)++;
	unsigned char shaOutput[64];

	mbedtls_sha512(reinterpret_cast<unsigned char*>(counter), 4, shaOutput, 0);
	
	unsigned char output[12]; // 4 for data and 8 reserve for function
	if(decrypt(input, 4, output, shaOutput, 16, tag, m_aesKey))
	{
		memcpy(&lenght, output, 4);
		return true;
	}
	(*counter)--;
	return false;
}