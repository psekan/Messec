//
// Created by Peter on 12.03.2016.
//

#include "messenger.h"
#include <mbedtls/gcm.h>
#include <string.h>
#include <limits.h>
#include <iostream>
#include <QDataStream>
#include "messageTypes.h"
#include <QHostAddress>

void Messenger::setAes(unsigned char aesKey[32], unsigned char aesIv[32]) {
	memcpy(this->m_aesKey, aesKey, sizeof(unsigned char) * 32);
	memcpy(this->m_aesIv, aesIv, sizeof(unsigned char) * 32);
}

Messenger::Messenger(std::string userName, unsigned int socket, unsigned char aesKey[32], unsigned char aesIv[32], uint32_t inCounter, uint32_t outCounter)
	: m_userName(userName), m_socket(socket), m_inCounter(inCounter), m_outCounter(outCounter) {
	this->setAes(aesKey, aesIv);
	m_isAlive = true;
}

Messenger::Messenger(QString ip, quint16 port, QString name, QObject *parent) : QThread(parent) {
	socket = new QTcpSocket(parent);
	QHostAddress addr(ip);
	socket->connectToHost(addr, port);
	std::cout << "port: " << port << " ip: " << ip.toStdString() << std::endl;
	if (!socket->waitForConnected()) 
	{
		std::cerr << "Could not connect to |" << ip.toStdString() << "|, " << addr.toString().toStdString() << " on port |" << port << "|" << std::endl;
		std::cout << "Connect failed" << std::endl;
		delete socket;
		m_isAlive = false;
	}
	else
	{
		std::cout << "Connection to " << name.toStdString() << " successful" << std::endl;
		m_isAlive = true;
	}
}

Messenger::Messenger(qintptr socketDescriptor, QObject *parent) : QThread(parent) {
	socket = new QTcpSocket(parent);
	if (socket->setSocketDescriptor(socketDescriptor))
	{
		std::cout << "Setting socket successful" << std::endl;
		m_isAlive = true;
	}
	else {
		std::cout << "Setting socket failed" << std::endl;
		m_isAlive = false;
	}

}

void Messenger::run() {
	connect(this, SIGNAL(finished()), this, SLOT(deleteLater()), Qt::DirectConnection);
	connect(socket, SIGNAL(readyRead()), this, SLOT(readData()), Qt::DirectConnection);
	connect(socket, SIGNAL(disconnected()), this, SLOT(quit()), Qt::DirectConnection);
	exec();
}

Messenger::~Messenger() {
	if (socket != nullptr)
	{
		socket->disconnectFromHost();
		delete socket;
	}
	std::cout << "Messenger destructor" << std::endl;
}

bool Messenger::isAlive() const {
	return m_isAlive;
}

void Messenger::exitCommunication() {
	m_isAlive = false;
}

bool Messenger::sendMessage(unsigned char messageType, size_t messageLength, const unsigned char* message) {
	unsigned char* preparedMessageBuffer = new unsigned char[messageLength + 21];
	if (!prepareMessageToSend(messageType, messageLength, message, preparedMessageBuffer)) {
		delete[] preparedMessageBuffer;
		return false;
	}
	//TODO send message by network
	delete[] preparedMessageBuffer;
	return false;
}

bool Messenger::prepareMessageToSend(unsigned char messageType, size_t messageLength, const unsigned char* message, unsigned char* preparedMessage) {
	size_t sizeOfMessageType = sizeof(unsigned char);
	size_t sizeOfCounter = sizeof(uint32_t);

	//Encrypt counter
	unsigned char* tag = new unsigned char[TAG_SIZE];
	if (!encrypt((unsigned char*)&m_outCounter, sizeOfCounter, preparedMessage, m_aesIv, 32, tag, m_aesKey)) {
		delete[] tag;
		return false;
	}

	//Copy tag of counter
	preparedMessage += sizeOfCounter;
	addToBuffer(preparedMessage, tag, TAG_SIZE);

	//Format of input = counter, counterTag, messageType, message
	size_t inputLength = sizeOfMessageType + messageLength;
	unsigned char *input = new unsigned char[inputLength], *bufferInput = input;
	addToBuffer(bufferInput, &messageType, sizeOfMessageType);
	addToBuffer(bufferInput, message, messageLength);

	//Compute tag and encrypted output
	if (!encrypt(input, inputLength, preparedMessage, m_aesIv, 32, tag, m_aesKey)) {
		delete[] input;
		delete[] tag;
		return false;
	}
	
	//Copy tag of message
	preparedMessage += inputLength;
	addToBuffer(preparedMessage, tag, TAG_SIZE);

	//Increase out counter
	++m_outCounter;

	//Free allocated memory
	delete[] input;
	delete[] tag;
	return true;	
}

bool Messenger::parseReceivedMessage(const unsigned char* receivedMessage, size_t receivedMessageLength, unsigned char& messageType, unsigned char* message) {
	size_t sizeOfMessageType = sizeof(unsigned char);
	size_t sizeOfCounter = sizeof(uint32_t);

	//Decrypt counter
	uint32_t counterInMessage = 0;
	if (!decrypt(receivedMessage, sizeOfCounter, (unsigned char*)&counterInMessage, m_aesIv, 32, receivedMessage + sizeOfCounter, m_aesKey)) {
		return false;
	}
	if (counterInMessage != m_inCounter) {
		return false;
	}

	//Decrypt messsage
	size_t encryptedMessageLength = receivedMessageLength - (2 * TAG_SIZE + sizeOfCounter);
	unsigned char* decryptedMessage = new unsigned char[encryptedMessageLength];
	const unsigned char* pointerBuffer = receivedMessage + sizeOfCounter + TAG_SIZE;
	if (!decrypt(pointerBuffer, encryptedMessageLength, decryptedMessage, m_aesIv, 32, pointerBuffer + encryptedMessageLength, m_aesKey)) {
		delete[] decryptedMessage;
		return false;
	}

	//Copy decrypted message
	memcpy(&messageType, decryptedMessage, sizeOfMessageType);
	memcpy(message, decryptedMessage + sizeOfMessageType, encryptedMessageLength - sizeOfMessageType);

	//Free allocated memory
	delete[] decryptedMessage;

	//Increase out counter
	++m_inCounter;
	return true;
}

bool Messenger::encrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, /*m_aesKey*/ key, 256);
	return !mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, inlen, iv, iv_len, nullptr, 0, input, output, TAG_SIZE, tag);
}

bool Messenger::decrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, const unsigned char* tag, const unsigned char* key)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, /*m_aesKey*/ key, 256);
	return !mbedtls_gcm_auth_decrypt(&ctx, inlen, iv, iv_len, nullptr, 0, tag, TAG_SIZE, input, output);
}

void Messenger::addToBuffer(unsigned char*& buffer, const unsigned char* data, size_t dataLength)
{
	memcpy(buffer, data, dataLength);
	buffer += dataLength;
}

void Messenger::readData() {
	std::cout << "Reading data" << std::endl;
	QDataStream input(socket);
	quint8 messageType;
	QString msg;
	//TODO decrypt
	input >> messageType;

	switch (messageType) {
	case MESSAGETYPE_MESSAGE:
		input >> msg;
		std::cout << msg.toStdString() << std::endl;
		break;
	default:
		std::cout << "Unknown message type" << std::endl;
		break;
	}

}
void Messenger::sendNotCrypted(QString msg) {
	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_MESSAGE;
	str << messageType;
	str << msg;
	socket->write(arr);
	socket->waitForBytesWritten();
}


void Messenger::quitMessenger() {
	this->exit(0);
}