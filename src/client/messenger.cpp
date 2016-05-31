//
// Created by Peter on 12.03.2016.
//

#include "messenger.h"
#include "crypto.h"
#include <mbedtls/dhm.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha512.h>
#include <string.h>
#include <limits.h>
#include <iostream>
#include <QDataStream>
#include "messageTypes.h"
#include <QHostAddress>
#include <QFile>
#include <QTextStream>

Messenger::Messenger(QString ip, quint16 port, unsigned char* dataToSendB, quint32 dataLength, unsigned char * randomNumbers, QObject *parent)
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

void Messenger::readData() {
	if (m_messageLength == 0) {
		unsigned char lenthAndTag[20];
		socket->read(reinterpret_cast<char*>(lenthAndTag), 20);
		decryptLength(m_messageLength, lenthAndTag, lenthAndTag + 4, &m_inCounter, m_aesKey);
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
		if (!parseMessage(m_readingBuffer, &m_inCounter, &messageType, array, m_aesKey))
		{
			std::cout << "Communication " << std::endl;
			exit();
		}
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

void Messenger::sendEncrypted(QString msg) {
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
	std::cout << "File '" << name.toStdString() << "' was received." << std::endl;
}

bool Messenger::serverHandshakeAuthentication(uint32_t initLength, const unsigned char* decryptedInit)
{
	quint8 messageType;
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
		delete[](decryptedInit - sizeof(uint8_t));
		return false;
	}
	if (messageType != MESSAGETYPE_AUTHENTICATION)
	{
		delete[](decryptedInit - sizeof(uint8_t));
		delete[](decryptedAuth - sizeof(uint8_t));
		return false;
	}
	if (memcmp(decryptedAuth, m_randomNumbers + 32, 16) != 0)
	{
		delete[](decryptedInit - sizeof(uint8_t));
		delete[](decryptedAuth - sizeof(uint8_t));
		return false;
	}

	std::cout << "chat with user: ";
	std::cout.write(reinterpret_cast<char const*>(decryptedInit + 64), initLength - 64) << std::endl;

	delete[](decryptedAuth - sizeof(uint8_t));
	delete[](decryptedInit - sizeof(uint8_t));
	return true;
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
		return false;
	}

	unsigned char *uResponse = new unsigned char[initLength];
	init.readRawData(reinterpret_cast<char*>(initTag), 16);
	init.readRawData(reinterpret_cast<char*>(uResponse), initLength);

	counter = 0;
	const unsigned char *decryptedInit = decryptMessage(&messageType, &counter, uResponse, initLength, initTag, m_clientMngrAes);
	delete[] uResponse;
	initLength -= sizeof(quint8); // - messagetype

	if (decryptedInit == nullptr)
	{
		delete[] (decryptedInit - sizeof(uint8_t));
		return false;
	}

	if (messageType == MESSAGETYPE_COMUNICATION_INIT) {
		unsigned char const* uNameFromServer = decryptedInit + 1 + 64;
		memcpy(m_randomNumbers, decryptedInit, 64);

		// DIFFIE HELLMAN
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

		if(encryptedDH == nullptr)
		{
			delete[](decryptedInit - sizeof(uint8_t));
			return false;
		}
		
		if(!encryptLength(outlen_ser, encryptedLengthAndTag, encryptedLengthAndTag + 4, &counter, m_randomNumbers))
		{
			delete[] encryptedDH;
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
			delete[](decryptedInit - sizeof(uint8_t));
			return false;
		}

		unsigned char *uDH = new unsigned char[DHLength];
		init.readRawData(reinterpret_cast<char*>(DHTag), 16);
		init.readRawData(reinterpret_cast<char*>(uDH), DHLength);

		counter = 0;
		const unsigned char *decryptedDH = decryptMessage(&messageType, &counter, uDH, DHLength, DHTag, m_randomNumbers);
		delete[] uDH;
		DHLength -= sizeof(quint8); // - messagetype

		if (decryptedDH == nullptr)
		{
			delete[](decryptedInit - sizeof(uint8_t));
			return false;
		}

		if (messageType != MESSAGETYPE_DIFFIE_HELMAN)
		{
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

		// AUTHENTICATION
		return serverHandshakeAuthentication(initLength, decryptedInit);
	}

	std::cout << "unknow data received";
	delete[](decryptedInit - sizeof(uint8_t));
	return false;
}


bool Messenger::clientHandshakeAuthentication()
{
	uint8_t messageType;
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
		delete[](decryptedAuth - sizeof(uint8_t));
		return false;
	}
	if (messageType != MESSAGETYPE_AUTHENTICATION)
	{
		delete[](decryptedAuth - sizeof(uint8_t));
		return false;
	}
	if (memcmp(decryptedAuth, m_randomNumbers + 48, 16) != 0)
	{
		delete[](decryptedAuth - sizeof(uint8_t));
		return false;
	}

	const unsigned char* authDataForB = encryptMessage(MESSAGETYPE_AUTHENTICATION, &m_outCounter, m_randomNumbers + 32, 16, authoutputLength, tagAuth, m_aesKey);  // encrypt dara for B

	if (authDataForB == nullptr)
	{
		delete[](decryptedAuth - sizeof(uint8_t));
		return false;
	}

	authentizationOutput.writeRawData(reinterpret_cast<const char*>(tagAuth), 16);
	authentizationOutput.writeRawData(reinterpret_cast<const char*>(authDataForB), authoutputLength);
	socket->write(arrayAuth);
	socket->waitForBytesWritten();
		
	delete[] authDataForB;
	delete[](decryptedAuth - sizeof(uint8_t));
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
	uint32_t counter = 0;
	uint32_t DHLength;
	unsigned char DHLengthAndTag[20];
	unsigned char DHTag[16];
	QDataStream DH(socket);
	uint8_t messageType;

	DH.readRawData(reinterpret_cast<char*>(DHLengthAndTag), 20);

	if (!decryptLength(DHLength, DHLengthAndTag, DHLengthAndTag + 4, &counter, m_randomNumbers))
	{
		return false;
	}

	unsigned char *uDH = new unsigned char[DHLength];
	DH.readRawData(reinterpret_cast<char*>(DHTag), 16);
	DH.readRawData(reinterpret_cast<char*>(uDH), DHLength);
	counter = 0;
	const unsigned char *decryptedDH = decryptMessage(&messageType, &counter, uDH, DHLength, DHTag, m_randomNumbers);
	delete[] uDH;

	DHLength -= sizeof(quint8); // - messagetype
	
	if (decryptedDH == nullptr)
	{
		delete[](decryptedDH - sizeof(quint8));
		return false;
	}

	if (messageType != MESSAGETYPE_DIFFIE_HELMAN)
	{
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
	
	if(encryptedDH == nullptr)
	{
		return false;
	}

	if(!encryptLength(outlen_cl, encryptedLengthAndTag, encryptedLengthAndTag + 4, &counter, m_randomNumbers))
	{
		delete[] encryptedDH;
		return false;
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

	// AUTHENTICATION
	return clientHandshakeAuthentication();
}
