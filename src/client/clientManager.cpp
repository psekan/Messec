//
// Created by Peter on 12.03.2016.
//

#include "clientManager.h"
#include <QHostAddress>
#include <cstring>
#include <iostream>
#include <QDataStream>
#include <messageTypes.h>
#include <mbedtls/entropy_poll.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include "crypto.h"

bool ClientManager::handleKeyDistribution()
{
	mbedtls_pk_context rsa_key;
	mbedtls_pk_init(&rsa_key);
	unsigned char buffer[32000];
	unsigned char output[512];
	size_t length;
	int result = 0;
	QDataStream u(m_serverSocket);

	std::cout << "waiting for rsa key" << std::endl;
	m_serverSocket->waitForReadyRead();
	u.readRawData(reinterpret_cast<char*>(buffer), 32000);

	std::cout.write(reinterpret_cast<char*>(buffer), 300);

	result += mbedtls_pk_parse_public_key(&rsa_key, buffer, 4096);
	if (result != 0)
	{
		std::cout << "parsing failed";
		return false;
	}
	generateRandomNumber(m_aesKey, 32);

	mbedtls_rsa_context *rsa = mbedtls_pk_rsa(rsa_key);
	//mbedtls_mpi_write_file("N:  ", &rsa->N, 16, stdout);

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *personalization = "sifrovanie_za_pomoci_RSA";
	initRandomContexts(entropy, ctr_drbg);
	result += mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		reinterpret_cast<const unsigned char *>(personalization), strlen(personalization));

	result += mbedtls_pk_encrypt(&rsa_key, m_aesKey, 32, output, &length, 512, mbedtls_ctr_drbg_random, &ctr_drbg);

	if (result != 0)
	{
		std::cout << "encrypt by rsa failed";
		return false;
	}


	std::cout << "sending aes key: ";
	std::cout.write(reinterpret_cast<char*>(m_aesKey), 32);
	std::cout << std::endl;
	
	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	str << length;
	str.writeRawData(reinterpret_cast<char*>(output), length);
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();

	mbedtls_pk_free(&rsa_key);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	// add check
	if (result != 0)
	{
		std::cout << "keys wasnt distributed correctly" << std::endl;
		return false;
	}

	return true;
}

ClientManager::ClientManager(): m_isLoggedIn(false), m_isConnected (false), m_serverSocket (nullptr), QTcpServer(0), m_inCounter(0), m_outCounter(0) {}

ClientManager::~ClientManager() {
	disconnect();
	exit(0);
}

void ClientManager::start() {
	if (!this->listen(QHostAddress::Any, 0)) {
		std::cout << "fail" << std::endl;
		qDebug() << "Server start failed";
		qDebug() << this->errorString();
		exit(0);
	}
	else
	{
		setPort(serverPort());
		std::cout << "success on port " << clientPort << std::endl; ////////////////////////debug print
	}
	}


bool ClientManager::signalconnect(QString ip, int port) {
	m_serverSocket = new QTcpSocket(this);
	QHostAddress addr(ip);
	m_serverSocket->connectToHost(addr, port);
	if (!m_serverSocket->waitForConnected()) {
		std::cerr << "Could not connect to " << ip.toStdString() << ", " << addr.toString().toStdString() << std::endl;
		std::cout << "Connect failed" << std::endl;
		return false;
	}

    if (handleKeyDistribution()) {
    	QByteArray arr;
		QDataStream str(&arr, QIODevice::WriteOnly);
		quint8 messageType = MESSAGETYPE_SEND_PORT;
		str << messageType;
		str << getPort();
		m_serverSocket->write(arr);
		m_serverSocket->waitForBytesWritten();
		m_isConnected = true;
		m_isConnected = true;
		std::cout << "Successfully connected" << std::endl;
		return true;
	}

	return false;
}

bool ClientManager::isConnected() const {
	return m_isConnected;
}

void ClientManager::disconnect() {
	if (m_serverSocket != nullptr) 
	{
		m_isConnected = false;
		m_serverSocket->disconnectFromHost();
		delete m_serverSocket;
		m_serverSocket = nullptr;
	}
}

bool ClientManager::signIn(QString userName, QString password) {
	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_SIGNIN;
	str << messageType;
	str << QString::fromStdString(userName.toStdString());
	str << QString::fromStdString(password.toStdString());
	std::cout << "seidng data to server" << std::endl;
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();
	std::cout << "waiting for response" << std::endl;
	m_serverSocket->waitForReadyRead();

	QString message;
	parseMessage(m_serverSocket, &messageType, &message);
	
	std::cout << "sign in ";	
	if(messageType == MESSAGETYPE_SIGNIN_SUCCESS)
	{
		std::cout << "successful" << std::endl;
		return true;
	}
	else if(messageType == MESSAGETYPE_SIGNIN_FAIL)
	{
		std::cout << "failed" << std::endl;
	}
	else
	{
		std::cout << "failed with incoming unknown message: " << messageType << " " << message.toStdString() << std::endl;
	}
	return false;
}

bool ClientManager::logIn(QString userName, QString password) {
	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_LOGIN;
	str << messageType;
	str << QString::fromStdString(userName.toStdString());
	str << QString::fromStdString(password.toStdString());
	std::cout << "sending data to server" << std::endl; /////////////////////////debug print
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();
	std::cout << "waiting for response" << std::endl; //////////////////////////debug print
	m_serverSocket->waitForReadyRead();

	QString message;
	parseMessage(m_serverSocket, &messageType, &message);
	
	std::cout << "log in ";
	std::cout << message.toStdString() << std::endl;

	if (messageType == MESSAGETYPE_LOGIN_SUCCESS)
	{
		std::cout << "successful" << std::endl;
		m_isLoggedIn = true;
		return true;
	}
	else if(messageType == MESSAGETYPE_LOGIN_FAIL)
	{
		std::cout << "failed" << std::endl;
	}
	else
	{
		std::cout << "failed with incoming unknown message: " << messageType << " " << message.toStdString() << std::endl;
	}
	return false;
}

bool ClientManager::isLoggedIn() const {
	return m_isLoggedIn;
}

void ClientManager::logOut() {
	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_LOGOUT;
	str << messageType;
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();
	m_isLoggedIn = false;
}

void ClientManager::getOnlineUsers() {
	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_GET_ONLINE_USERS;
	str << messageType;
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();
	m_serverSocket->waitForReadyRead();

	QString message;
	parseMessage(m_serverSocket, &messageType, &message);

	if (messageType != MESSAGETYPE_GET_ONLINE_USERS)
	{
		std::cerr << "Error while getting all online users" << std::endl;
	}
	else
	{
		QStringList users = message.split("|#|");
		std::cout << "Online users:" << std::endl;
		std::cout << "---------" << std::endl;
		for (QString user : users)
		{
			std::cout << user.toStdString() << std::endl;
		}
		std::cout << "---------" << std::endl;
	}
}

void ClientManager::parseMessage(QTcpSocket* socket, quint8* message_type, QString* message)
{
	QDataStream u(socket);
	unsigned char tag[16];
	size_t messageLengt;
	u >> messageLengt;
	unsigned char *uMessage = new unsigned char[messageLengt];
	u.readRawData(reinterpret_cast<char*>(tag), 16);

	
	u.readRawData(reinterpret_cast<char*>(uMessage), messageLengt);
	size_t decryptedLength;

	const unsigned char* pMessage = decryptMessage(message_type, &m_inCounter, uMessage, messageLengt, nullptr, tag, m_aesKey);
	if (pMessage == nullptr)
	{
		std::cout << "decryption fail" << std::endl;
		delete[] uMessage;
		return;
	}
	//uMessage[messageLengt] = '\0';
	std::string messageString = std::string(reinterpret_cast<const char *>(pMessage), messageLengt - sizeof(quint8));
	*message = QString::fromStdString(messageString);
	delete[] uMessage;
}

std::vector<Messenger*> ClientManager::getMessengers() const {
	return m_messengers;
}

Messenger* ClientManager::newMessenger(qintptr socketDescriptor, QString userName) {
	/*Messenger* mes = new Messenger(socketDescriptor, userName, this);
	m_peerSocket = new QTcpSocket(this);
	m_peerSocket->setSocketDescriptor(socketDescriptor);
	mes->start();
	//QMutexLocker locker(&mutex);
	m_messengers.push_back(mes);
	return mes;*/
	return nullptr;
}

void ClientManager::deleteMessenger() {
	Messenger* msngr = dynamic_cast<Messenger*>(sender());
	if (msngr == nullptr)
	{
		std::cerr << "Messenger is null - deleteMessenger\n";
		return;
	}

	//QMutexLocker locker(&mutex);
	auto it = std::find(m_messengers.begin(), m_messengers.end(), msngr);
	m_messengers.erase(it);
	delete msngr;
	std::cout << "Messenger deleted" << std::endl; ////////////////////////////////////debug print
}



bool ClientManager::startCommunicationWith(QString userName) {
	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_GET_PARTNER;
	str << messageType;
	str << userName;
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();
	m_serverSocket->waitForReadyRead();

	QDataStream response(m_serverSocket);
	response >> messageType;
	if (messageType == MESSAGETYPE_PARTNER_INFO)
	{
		QString ip;
		quint16 port;
		response >> port >> ip;
		/*QTcpSocket* m_peerSocket = new QTcpSocket(this);
		QHostAddress addr(ip);
		m_peerSocket->connectToHost(addr, port);
		if (!m_peerSocket->waitForConnected()) {
			std::cerr << "Could not connect to |" << ip.toStdString() << "|, " << addr.toString().toStdString() << " on port |" << port << "|" << std::endl;
			std::cout << "Connect failed" << std::endl;
			return false;
		}*/
		Messenger* msngr = new Messenger(ip, port, userName, this);
		msngr->start();
		connect(msngr, SIGNAL(finished()), this, SLOT(deleteMessenger()));
		connect(this, SIGNAL(sendSignal(QString)), msngr, SLOT(sendNotCrypted(QString)));
		connect(this, SIGNAL(finished()), msngr, SLOT(quit()), Qt::DirectConnection);
		m_messengers.push_back(msngr);
		std::cout << "Connection with " << /*userName.toStdString() <<*/ " is ready" << std::endl;
		return true;
	}
	else if (messageType == MESSAGETYPE_PARTNER_NOT_READY)
		std::cout << "User " << userName.toStdString() << " is not ready for communication" << std::endl;
	else 		
		std::cout << "Incoming unknown messagetype: " << messageType << std::endl;
	return false;
}


void ClientManager::incomingConnection(qintptr socketDescriptor)
{
	std::cout << "Incoming connection " << std::endl;///////////////////////debug print
	Messenger* mes = new Messenger(socketDescriptor, this);
	mes->start();
	connect(mes, SIGNAL(finished()), this, SLOT(deleteMessenger()));
	connect(this, SIGNAL(sendSignal(QString)), mes, SLOT(sendNotCrypted(QString)));
	connect(this, SIGNAL(finished()), mes, SLOT(quit()), Qt::DirectConnection);
	m_messengers.push_back(mes);
}

void ClientManager::sendToMessenger(QString msg) {
	emit sendSignal(msg);
	/*QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_MESSAGE;
	str << messageType;
	str << msg;
	m_peerSocket->write(arr);
	m_peerSocket->waitForBytesWritten();*/
}
