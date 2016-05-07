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

Messenger::Messenger(QString ip, quint16 port, QString name, unsigned char* dataToSendB, quint32 dataLength, unsigned char * randomNumbers, QObject *parent)
	: QThread(parent), m_isAlive(false), m_inCounter(0), m_outCounter(0) {
	socket = new QTcpSocket(parent);
	QHostAddress addr(ip);
	socket->connectToHost(addr, port);
	if (!socket->waitForConnected()) {
		std::cout << "Could not connect to " << addr.toString().toStdString() << " on port " << port << std::endl;
	}
	else
	{
		memcpy(m_randomNumbers, randomNumbers, 64);
		QByteArray array;
		QDataStream output(&array, QIODevice::WriteOnly);
		output.writeRawData(reinterpret_cast<const char*>(dataToSendB), dataLength);
		socket->write(array);
		socket->waitForBytesWritten();
		delete[] dataToSendB;
	}

}

Messenger::Messenger(qintptr socketDescriptor, QObject *parent, unsigned char* clientMngrAes) : QThread(parent), m_isAlive(false), m_clientMngrAes(clientMngrAes), m_inCounter(0), m_outCounter(0) {
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
	if (m_messageLength == 0) {
		std::cout << "Reading data" << std::endl;
		socket->read(reinterpret_cast<char*>(&m_messageLength), sizeof(size_t));
		m_messageLength += TAG_SIZE; //need to read also tag to buffer for parse
	}

	char *uMessage = new char[m_messageLength];
	qint64 readLength = socket->read(uMessage, m_messageLength);
	m_readingBuffer.append(uMessage, readLength);
	delete[] uMessage;

	if (m_readingBuffer.size() == m_messageLength)
	{
		quint8 messageType;
		QByteArray array;
		parseMessage(m_readingBuffer, &m_inCounter, &messageType, array, m_aesKey);
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

		m_readingBuffer.clear();
		m_messageLength = 0;
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

	socket->waitForReadyRead();
	uint32_t counter = 0;
	quint8 messageType;
	uint32_t initLength;
	unsigned char initLengthAndTag[20];
	QDataStream init(socket);
	unsigned char initTag[16];

	init.readRawData(reinterpret_cast<char*>(initLengthAndTag), 20);

	if (!decryptLength(initLength, initLengthAndTag, initLengthAndTag + 4, &counter, m_clientMngrAes))
	{
		std::cout << "decrypt of data from server length failed" << std::endl;
		return false;
	}

	unsigned char *uResponse = new unsigned char[initLength];
	init.readRawData(reinterpret_cast<char*>(initTag), 16);
	init.readRawData(reinterpret_cast<char*>(uResponse), initLength);

	counter = 0;
	const unsigned char *decryptedInit = decryptMessage(&messageType, &counter, uResponse, initLength, initTag, m_clientMngrAes);
	initLength -= sizeof(quint8); // - messagetype

	if (decryptedInit == nullptr)
	{
		std::cout << "decrypt of of data from server failed" << std::endl;
		delete[] (decryptedInit - sizeof(uint8_t));
		return false;
	}

	if (messageType == MESSAGETYPE_COMUNICATION_INIT) {

		std::cout << "comunication is being initialized" << std::endl;
		unsigned char const* uNameFromServer = decryptedInit + 1 + 64;
		memcpy(m_randomNumbers, decryptedInit, 64);

		// DIFIE HELLMAN
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
			delete[](decryptedInit - sizeof(uint8_t));
			return false;
		}

		//encrypt and send buf_ser of length outlen_ser
		counter = 0;
		unsigned char tag[16];
		const unsigned char* encryptedDH = encryptMessage(MESSAGETYPE_DIFFIE_HELMAN, &counter, buf_ser, outlen_ser, outlen_ser, tag, m_randomNumbers);
		unsigned char encryptedLengthAndTag[20];
		counter = 0;
		
		if(!encryptLength(outlen_ser, encryptedLengthAndTag, encryptedLengthAndTag + 4, &counter, m_randomNumbers))
		{
			std::cout << "encrypt of DH length failed" << std::endl;
			delete[](decryptedInit - sizeof(uint8_t));
			return false;
		}

		QByteArray array;
		QDataStream output(&array, QIODevice::WriteOnly);
		output.writeRawData(reinterpret_cast<const char*>(encryptedLengthAndTag), 20);
		output.writeRawData(reinterpret_cast<const char*>(tag), 16);
		output.writeRawData(reinterpret_cast<const char*>(encryptedDH), outlen_ser);
		socket->write(array);
		socket->waitForBytesWritten();
		delete[] encryptedDH;
		///////////

		memset(buf_ser, 0, sizeof(buf_ser));

		//receive and decrypt clients buf_cl to buf_ser
		socket->waitForReadyRead();
		counter = 0;
		uint32_t DHLength;
		unsigned char DHLengthAndTag[20];
		unsigned char DHTag[16];

		init.readRawData(reinterpret_cast<char*>(DHLengthAndTag), 20);

		if (!decryptLength(DHLength, DHLengthAndTag, DHLengthAndTag + 4, &counter, m_randomNumbers))
		{
			std::cout << "decrypt of DH length failed" << std::endl;
			delete[](decryptedInit - sizeof(uint8_t));
			return false;
		}

		unsigned char *uDH = new unsigned char[DHLength];
		init.readRawData(reinterpret_cast<char*>(DHTag), 16);
		init.readRawData(reinterpret_cast<char*>(uDH), DHLength);

		counter = 0;
		const unsigned char *decryptedDH = decryptMessage(&messageType, &counter, uDH, DHLength, DHTag, m_randomNumbers);
		DHLength -= sizeof(quint8); // - messagetype

		if (decryptedDH == nullptr)
		{
			std::cout << "decrypt of DH failed" << std::endl;
			delete[](decryptedInit - sizeof(uint8_t));
			delete[] (decryptedDH - sizeof(quint8));
			return false;
		}

		if (messageType != MESSAGETYPE_DIFFIE_HELMAN)
		{
			std::cout << "DIFIE HELMAN ended before completed - wrong recieved data" << std::endl;
			delete[](decryptedInit - sizeof(uint8_t));
			delete[](decryptedDH - sizeof(quint8));
			return false;
		}

		memcpy(buf_ser, decryptedDH, DHLength);
		delete[](decryptedDH - sizeof(quint8));
		/////////////


		if (mbedtls_dhm_read_public(&dhm_ser, buf_ser, dhm_ser.len)) {
			delete[](decryptedInit - sizeof(uint8_t));
			return false;
		}
		if (mbedtls_dhm_calc_secret(&dhm_ser, buf_ser, sizeof(buf_ser), &outlen_ser, mbedtls_ctr_drbg_random, &ctr_drbg_ser)) {
			delete[](decryptedInit - sizeof(uint8_t));
			return false;
		}
		unsigned char hash[64];
		mbedtls_sha512(reinterpret_cast<const unsigned char*>(buf_ser), outlen_ser, hash, 0);
		memcpy(m_aesKey, hash, 32);
		mbedtls_dhm_free(&dhm_ser);

		std::cout << "aes messenger key: ";							//////////////////////////////////debug print
		std::cout.write(reinterpret_cast<const char*>(m_aesKey), 32);
		std::cout << std::endl;

		// AUTHENTICATION
		QByteArray arrayAuth;
		QDataStream authentizationOutput(&arrayAuth, QIODevice::WriteOnly);
		QDataStream authentizationInput(socket);
		uint32_t authoutputLength;
		unsigned char tagAuth[16];
		unsigned char authFromA[16 + sizeof(uint8_t)];
		unsigned char tagFromA[16];

		const unsigned char* authDataForA = encryptMessage(MESSAGETYPE_AUTHENTICATION, &m_outCounter, m_randomNumbers + 48, 16, authoutputLength, tagAuth, m_aesKey);  // encrypt dara for A

		if (authDataForA == nullptr)
		{
			std::cout << "encrypt of data to A failed" << std::endl;
			delete[](decryptedInit - sizeof(uint8_t));
			return false;
		}

		authentizationOutput.writeRawData(reinterpret_cast<const char*>(tagAuth), 16);
		authentizationOutput.writeRawData(reinterpret_cast<const char*>(authDataForA), 16 + sizeof(uint8_t));
		socket->write(arrayAuth);
		socket->waitForBytesWritten();

		socket->waitForReadyRead();
		authentizationInput.readRawData(reinterpret_cast<char*>(tagFromA), 16);
		authentizationInput.readRawData(reinterpret_cast<char*>(authFromA), 16 + sizeof(uint8_t));

		const unsigned char *decryptedAuth = decryptMessage(&messageType, &m_inCounter, authFromA, 16 + sizeof(uint8_t), tagFromA, m_aesKey);

		if (decryptedAuth == nullptr)
		{
			std::cout << "decrypt of authentization message failed" << std::endl;
			delete[](decryptedInit - sizeof(uint8_t));
			delete[](decryptedAuth - sizeof(uint8_t));
			return false;
		}
		if (messageType != MESSAGETYPE_AUTHENTICATION)
		{
			std::cout << "authentization ended before completed - wrong recieved data" << std::endl;
			delete[](decryptedInit - sizeof(uint8_t));
			delete[](decryptedAuth - sizeof(uint8_t));
			return false;
		}
		if (memcmp(decryptedAuth, m_randomNumbers + 32, 16) != 0)
		{
			std::cout << "authentiacation failed" << std::endl;
			delete[](decryptedInit - sizeof(uint8_t));
			delete[](decryptedAuth - sizeof(uint8_t));
			return false;
		}

		std::cout << "your are now chatting with user: ";
		std::cout.write(reinterpret_cast<char const*>(decryptedInit + 64), initLength - 64) << std::endl;

		delete[](decryptedAuth - sizeof(uint8_t));
		delete[](decryptedInit - sizeof(uint8_t));
		return true;
	}

	std::cout << "unknow data was recieved";
	delete[](decryptedInit - sizeof(uint8_t));
	return false;
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
	uint32_t counter = 0;
	uint32_t DHLength;
	unsigned char DHLengthAndTag[20];
	unsigned char DHTag[16];
	QDataStream DH(socket);
	uint8_t messageType;

	DH.readRawData(reinterpret_cast<char*>(DHLengthAndTag), 20);

	if (!decryptLength(DHLength, DHLengthAndTag, DHLengthAndTag + 4, &counter, m_randomNumbers))
	{
		std::cout << "decrypt of DH length failed" << std::endl;
		return false;
	}

	unsigned char *uDH = new unsigned char[DHLength];
	DH.readRawData(reinterpret_cast<char*>(DHTag), 16);
	DH.readRawData(reinterpret_cast<char*>(uDH), DHLength);
	counter = 0;
	const unsigned char *decryptedDH = decryptMessage(&messageType, &counter, uDH, DHLength, DHTag, m_randomNumbers);

	DHLength -= sizeof(quint8); // - messagetype
	
	if (decryptedDH == nullptr)
	{
		std::cout << "decrypt of DH failed" << std::endl;
		delete[](decryptedDH - sizeof(quint8));
		return false;
	}

	if (messageType != MESSAGETYPE_DIFFIE_HELMAN)
	{
		std::cout << "DIFIE HELMAN ended before completed - wrong recieved data" << std::endl;
		delete[](decryptedDH - sizeof(quint8));
		return false;
	}
	memcpy(buf_cl, decryptedDH, DHLength);
	delete[](decryptedDH - sizeof(quint8));
	/////////////

	unsigned char* p = buf_cl;
	if (mbedtls_dhm_read_params(&dhm_cl, &p, buf_cl + DHLength)) {
		return false;
	}

	outlen_cl = dhm_cl.len;
	if (mbedtls_dhm_make_public(&dhm_cl, (int)dhm_cl.len, buf_cl, outlen_cl, mbedtls_ctr_drbg_random, &ctr_drbg_cl)) {
		return false;
	}

	//send buf_cl
	counter = 0;
	unsigned char tag[16];
	const unsigned char* encryptedDH = encryptMessage(MESSAGETYPE_DIFFIE_HELMAN, &counter, buf_cl, outlen_cl, outlen_cl, tag, m_randomNumbers);
	unsigned char encryptedLengthAndTag[20];
	counter = 0;
	if(!encryptLength(outlen_cl, encryptedLengthAndTag, encryptedLengthAndTag + 4, &counter, m_randomNumbers))
	{
		std::cout << "encrypt of DH lenght failed" << std::endl;
	}

	QByteArray array;
	QDataStream output(&array, QIODevice::WriteOnly);
	output.writeRawData(reinterpret_cast<const char*>(encryptedLengthAndTag), 20);
	output.writeRawData(reinterpret_cast<const char*>(tag), 16);
	output.writeRawData(reinterpret_cast<const char*>(encryptedDH), outlen_cl);
	socket->write(array);
	socket->waitForBytesWritten();

	delete[] encryptedDH;
	////////////

	if (mbedtls_dhm_calc_secret(&dhm_cl, buf_cl, sizeof(buf_cl), &outlen_cl, mbedtls_ctr_drbg_random, &ctr_drbg_cl)) {
		return false;
	}
	unsigned char hash[64];
	mbedtls_sha512(reinterpret_cast<const unsigned char*>(buf_cl), outlen_cl, hash, 0);
	memcpy(m_aesKey, hash, 32);
	mbedtls_dhm_free(&dhm_cl);

	std::cout << "aes messenger key: ";						//////////////////////////////////debug print
	std::cout.write(reinterpret_cast<const char*>(m_aesKey), 32);
	std::cout << std::endl;

	// AUTHENTICATION
	QByteArray arrayAuth;
	QDataStream authentizationOutput(&arrayAuth, QIODevice::WriteOnly);
	QDataStream authentizationInput(socket);
	uint32_t authoutputLength;
	unsigned char tagAuth[16];
	unsigned char authFromB[16 + sizeof(uint8_t)];
	unsigned char tagFromB[16];

	socket->waitForReadyRead();
	authentizationInput.readRawData(reinterpret_cast<char*>(tagFromB), 16);
	authentizationInput.readRawData(reinterpret_cast<char*>(authFromB), 16 + sizeof(uint8_t));

	const unsigned char *decryptedAuth = decryptMessage(&messageType, &m_inCounter, authFromB, 16 + sizeof(uint8_t), tagFromB, m_aesKey);

	if (decryptedAuth == nullptr)
	{
		std::cout << "decrypt of authentization message failed" << std::endl;
		delete[](decryptedAuth - sizeof(uint8_t));
		return false;
	}
	if (messageType != MESSAGETYPE_AUTHENTICATION)
	{
		std::cout << "authentization ended before completed - wrong recieved data" << std::endl;
		delete[](decryptedAuth - sizeof(uint8_t));
		return false;
	}
	if (memcmp(decryptedAuth, m_randomNumbers + 48, 16) != 0)
	{
		std::cout << "authentiacation failed" << std::endl;
		delete[](decryptedAuth - sizeof(uint8_t));
		return false;
	}

	const unsigned char* authDataForB = encryptMessage(MESSAGETYPE_AUTHENTICATION, &m_outCounter, m_randomNumbers + 32, 16, authoutputLength, tagAuth, m_aesKey);  // encrypt dara for B

	if (authDataForB == nullptr)
	{
		std::cout << "encrypt of data to B failed" << std::endl;
		return false;
	}

	authentizationOutput.writeRawData(reinterpret_cast<const char*>(tagAuth), 16);
	authentizationOutput.writeRawData(reinterpret_cast<const char*>(authDataForB), authoutputLength);
	socket->write(arrayAuth);
	socket->waitForBytesWritten();
	
	std::cout << "your are now chatting with requester user" << std::endl;
	
	delete[](decryptedAuth - sizeof(uint8_t));
	return true;
}
