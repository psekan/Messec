//
// Created by Peter on 12.03.2016.
//

#include "messenger.h"
#include "crypto.h"
#include <mbedtls\dhm.h>
#include <mbedtls\gcm.h>
#include <mbedtls\sha512.h>
#include <string.h>
#include <limits.h>
#include <iostream>
#include <QDataStream>
#include "messageTypes.h"
#include <QHostAddress>
#include <QFile>
#include <QTextStream>

void Messenger::setAes(unsigned char aesKey[32], unsigned char aesIv[32]) {
	memcpy(this->m_aesKey, aesKey, sizeof(unsigned char) * 32);
	memcpy(this->m_aesIv, aesIv, sizeof(unsigned char) * 32);
}

Messenger::Messenger(std::string userName, unsigned int socket, unsigned char aesKey[32], unsigned char aesIv[32], uint32_t inCounter, uint32_t outCounter)
	: m_userName(userName), m_socket(socket), m_inCounter(inCounter), m_outCounter(outCounter) {
	this->setAes(aesKey, aesIv);
	m_isAlive = true;
}

Messenger::Messenger(QString ip, quint16 port, QString name, QObject *parent) : QThread(parent), m_isAlive(false){
	socket = new QTcpSocket(parent);
	QHostAddress addr(ip);
	socket->connectToHost(addr, port);
	if (!socket->waitForConnected()) 
		std::cout << "Could not connect to " << addr.toString().toStdString() << " on port " << port << std::endl;
	
}

Messenger::Messenger(qintptr socketDescriptor, QObject *parent) : QThread(parent), m_isAlive(false) {
	socket = new QTcpSocket(parent);
	if (!socket->setSocketDescriptor(socketDescriptor)) {
		std::cout << "Connection failed" << std::endl;
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
}

bool Messenger::isAlive() const {
	return m_isAlive;
}

void Messenger::exitCommunication() {
	m_isAlive = false;
}

bool Messenger::encrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
	return !mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, inlen, iv, iv_len, nullptr, 0, input, output, 16, tag);
}

bool Messenger::decrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, const unsigned char* tag, const unsigned char* key)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, /*m_aesKey*/ key, 256);
	return !mbedtls_gcm_auth_decrypt(&ctx, inlen, iv, iv_len, nullptr, 0, tag, 16, input, output);
}

bool Messenger::sendMessageC(unsigned char messageType, size_t messageLength, const unsigned char* message) {
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

void Messenger::addToBuffer(unsigned char*& buffer, const unsigned char* data, size_t dataLength)
{
	memcpy(buffer, data, dataLength);
	buffer += dataLength;
}

void Messenger::readData() {
	std::cout << "Reading data" << std::endl;
	quint8 messageType;
	QByteArray array;
	parseMessage(socket, &m_inCounter, &messageType, array, m_aesKey);
	QDataStream stream(&array, QIODevice::ReadOnly);

	if (messageType == MESSAGETYPE_MESSAGE) {
		QString message;
		stream >> message;
		std::cout << message.toStdString() << std::endl;
	} 
	else if (messageType == MESSAGETYPE_FILE) {
		QString fileName;
		QByteArray bytes;
		stream >> fileName;
		stream >> bytes;
		saveFile(fileName, bytes);
	}
	else
	{
		std::cout << "Unknown message type" << std::endl;	
	}

}

void Messenger::sendNotCrypted(QString msg) {
	QByteArray array;
	QDataStream stream(&array, QIODevice::WriteOnly);
	stream << msg;
	sendMessage(socket, &m_outCounter, MESSAGETYPE_MESSAGE, array, m_aesKey);
}

void Messenger::quitMessenger() {
	exit(0);
}

void Messenger::sendFile(QString msg)
{
	QFile f(msg);
	if (!f.open(QFile::ReadOnly)) {
		std::cout << "Cannot open file '" << msg.toStdString() << "'" << std::endl;
		return;
	}

	QByteArray array;
	QDataStream stream(&array, QIODevice::WriteOnly);
	stream << msg;
	stream << f.readAll();
	sendMessage(socket, &m_outCounter, MESSAGETYPE_FILE, array, m_aesKey);

	f.close();
}

void Messenger::saveFile(QString name, QByteArray content)
{
	QFile f(name);
	if (!f.open(QFile::WriteOnly)) {
		std::cout << "Cannot open file '" << name.toStdString() << "'" << std::endl;
		return;
	}
	f.write(content);
	f.close();
}

bool Messenger::serverHandshake() {
	unsigned char buf_ser[2048];
	size_t outlen_ser;
	mbedtls_dhm_context dhm_ser;
	mbedtls_dhm_init(&dhm_ser);
	mbedtls_entropy_context entropy_ser;
	mbedtls_ctr_drbg_context ctr_drbg_ser;
	const char *personalization_ser = "server_personalization_of_random_generator_for_Diffie-Hellman ";

	initRandomContexts(entropy_ser, ctr_drbg_ser);
	mbedtls_ctr_drbg_seed(&ctr_drbg_ser, mbedtls_entropy_func, &entropy_ser, reinterpret_cast<const unsigned char *>(personalization_ser), strlen(personalization_ser));
	mbedtls_mpi_read_string(&dhm_ser.P, 16, MBEDTLS_DHM_RFC3526_MODP_2048_P);
	mbedtls_mpi_read_string(&dhm_ser.G, 16, MBEDTLS_DHM_RFC3526_MODP_2048_G);
	if (mbedtls_dhm_make_params(&dhm_ser, (int)mbedtls_mpi_size(&dhm_ser.P), buf_ser, &outlen_ser, mbedtls_ctr_drbg_random, &ctr_drbg_ser)) {
		return false;
	}
	
	//send buf_ser of length outlen_ser
	QByteArray array;
	QDataStream output(&array, QIODevice::WriteOnly);
	output.writeRawData(reinterpret_cast<const char*>(&outlen_ser), sizeof(size_t));
	output.writeRawData(reinterpret_cast<const char*>(buf_ser), outlen_ser);
	socket->write(array);
	socket->waitForBytesWritten();
	///////////

	memset(buf_ser, 0, sizeof(buf_ser));

	//receive clients buf_cl to buf_ser
	socket->waitForReadyRead();
	QDataStream mySocket(socket);
	size_t messageLength;
	mySocket.readRawData(reinterpret_cast<char*>(&messageLength), sizeof(size_t));
	mySocket.readRawData(reinterpret_cast<char*>(buf_ser), messageLength);
	/////////////

	if (mbedtls_dhm_read_public(&dhm_ser, buf_ser, dhm_ser.len)) {
		return false;
	}
	if (mbedtls_dhm_calc_secret(&dhm_ser, buf_ser, sizeof(buf_ser), &outlen_ser, mbedtls_ctr_drbg_random, &ctr_drbg_ser)) {
		return false;
	}

	mbedtls_sha512_context ctx;
	unsigned char hash[64];
	mbedtls_sha512_init(&ctx);
	mbedtls_sha512(reinterpret_cast<const unsigned char*>(buf_ser), outlen_ser, hash, 0);
	memcpy(m_aesKey, hash, 32);
	mbedtls_sha512_free(&ctx);
	mbedtls_dhm_free(&dhm_ser);

	std::cout << "aes messenger key: ";							//////////////////////////////////debug print
	std::cout.write(reinterpret_cast<const char*>(m_aesKey), 32); 
	std::cout << std::endl;
	return true;
}


bool Messenger::clientHandshake() {
	unsigned char buf_cl[2048];
	size_t outlen_cl;
	mbedtls_dhm_context dhm_cl;
	mbedtls_dhm_init(&dhm_cl);
	mbedtls_entropy_context entropy_cl;
	mbedtls_ctr_drbg_context ctr_drbg_cl;
	const char *personalization_cl = "client_personalization_of_random_generator_for_Diffie-Hellman ";

	initRandomContexts(entropy_cl, ctr_drbg_cl);
	mbedtls_ctr_drbg_seed(&ctr_drbg_cl, mbedtls_entropy_func, &entropy_cl, reinterpret_cast<const unsigned char *>(personalization_cl), strlen(personalization_cl));
	
	//read to buf_cl and len to outlen_cl
	socket->waitForReadyRead();
	QDataStream mySocket(socket);
	mySocket.readRawData(reinterpret_cast<char*>(&outlen_cl), sizeof(size_t));
	mySocket.readRawData(reinterpret_cast<char*>(buf_cl), outlen_cl);
	/////////////
	
	unsigned char* p = buf_cl;
	if (mbedtls_dhm_read_params(&dhm_cl, &p, buf_cl+outlen_cl)) {
		return false;
	}

	outlen_cl = dhm_cl.len;
	if (mbedtls_dhm_make_public(&dhm_cl, (int)dhm_cl.len, buf_cl, outlen_cl, mbedtls_ctr_drbg_random, &ctr_drbg_cl)) {
		return false;
	}
	
	//send buf_cl
	QByteArray array;
	QDataStream output(&array, QIODevice::WriteOnly);
	output.writeRawData(reinterpret_cast<const char*>(&outlen_cl), sizeof(size_t));
	output.writeRawData(reinterpret_cast<const char*>(buf_cl), outlen_cl);
	socket->write(array);
	socket->waitForBytesWritten();
	////////////

	if (mbedtls_dhm_calc_secret(&dhm_cl, buf_cl, sizeof(buf_cl), &outlen_cl, mbedtls_ctr_drbg_random, &ctr_drbg_cl)) {
		return false;
	}
	mbedtls_sha512_context ctx;
	unsigned char hash[64];
	mbedtls_sha512_init(&ctx);
	mbedtls_sha512(reinterpret_cast<const unsigned char*>(buf_cl), outlen_cl, hash, 0);
	memcpy(m_aesKey, hash, 32);
	mbedtls_sha512_free(&ctx);
	mbedtls_dhm_free(&dhm_cl);

	std::cout << "aes messenger key: ";						//////////////////////////////////debug print
	std::cout.write(reinterpret_cast<const char*>(m_aesKey), 32); 
	std::cout << std::endl;
	return true;
}
