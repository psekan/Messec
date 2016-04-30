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

	result += mbedtls_pk_parse_public_key(&rsa_key, buffer, 4096);
	if (result != 0)
	{
		std::cout << "parsing failed";
		return false;
	}
	generateRandomNumber(m_aesKey, 32);
	unsigned char aesAndPort[34];

	memcpy(aesAndPort, m_aesKey, 32);
	memcpy(aesAndPort + 32, &m_clientPort, 2);

	mbedtls_rsa_context *rsa = mbedtls_pk_rsa(rsa_key);
	mbedtls_mpi_write_file("Modulus:  ", &rsa->N, 16, stdout);
	mbedtls_mpi_write_file("Public exponent:  ", &rsa->E, 16, stdout);
	bool answered = false;

	std::cout << "Do you trust this key? y/n" << std::endl;

	while (!answered)
	{
		char answer = getchar();
		switch (answer)
		{
		case 'y':
			answered = true;
			getchar();
			break;
		case 'n':
			getchar();
			return false;
		case '\n':
			break;
		default: std::cout << "please type 'y' if you do or 'n' if you dont" << std::endl;
			getchar();
			break;
		}
	}

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *personalization = "sifrovanie_za_pomoci_RSA";
	initRandomContexts(entropy, ctr_drbg);
	result += mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		reinterpret_cast<const unsigned char *>(personalization), strlen(personalization));

	result += mbedtls_pk_encrypt(&rsa_key, aesAndPort, 34, output, &length, 512, mbedtls_ctr_drbg_random, &ctr_drbg);

	if (result != 0)
	{
		std::cout << "encrypt by rsa failed";
		return false;
	}


	std::cout << "sending aes key: ";
	std::cout.write(reinterpret_cast<char*>(m_aesKey), 32);
	std::cout << std::endl;

	std::cout << "sending port: " << m_clientPort << std::endl;

	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	str << length;
	str.writeRawData(reinterpret_cast<char*>(output), length);
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();

	mbedtls_pk_free(&rsa_key);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);

	if (result != 0)
	{
		std::cout << "keys wasnt distributed correctly" << std::endl;
		return false;
	}

	return true;
}

ClientManager::ClientManager() : m_isLoggedIn(false), m_isConnected(false), m_serverSocket(nullptr), QTcpServer(0) {}

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
		std::cout << "success on port " << m_clientPort << std::endl; ////////////////////////debug print
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
		m_isConnected = true;
		m_outCounter = 0;
		m_inCounter = 0;
		std::cout << "Successfully connected" << std::endl;
		return true;
	}
	std::cout << "Coudlnt connect" << std::endl;
	return false;
}

bool ClientManager::isConnected() const {
	return m_isConnected;
}

void ClientManager::disconnect() {
	if (m_serverSocket != nullptr)
	{
		m_isLoggedIn = false;
		m_isConnected = false;
		m_serverSocket->disconnectFromHost();
		delete m_serverSocket;
		m_serverSocket = nullptr;
	}
}

bool ClientManager::signIn(QString userName, QString password) {
	quint8 messageType = MESSAGETYPE_SIGNIN;
	QString messageSent = QString::fromStdString(userName.toStdString()) + "|#|" + QString::fromStdString(password.toStdString());
	std::cout << "seidng data to server" << std::endl;
	sendMessage(m_serverSocket, &m_outCounter, messageType, messageSent, m_aesKey);
	std::cout << "waiting for response" << std::endl;
	m_serverSocket->waitForReadyRead();

	QString messageRec;
	parseMessage(m_serverSocket, &m_inCounter, &messageType, &messageRec, m_aesKey);

	std::cout << "sign in ";

	if (messageType == MESSAGETYPE_SIGNIN_SUCCESS)
	{
		std::cout << "successful" << std::endl;
		return true;
	}
	else if (messageType == MESSAGETYPE_SIGNIN_FAIL)
	{
		std::cout << "failed" << std::endl;
	}
	else
	{
		std::cout << "failed with incoming unknown message: " << messageType << messageRec.toStdString() << std::endl;
	}
	return false;
}

bool ClientManager::logIn(QString userName, QString password) {
	quint8 messageType = MESSAGETYPE_LOGIN;
	QString messageSent = QString::fromStdString(userName.toStdString()) + "|#|" + QString::fromStdString(password.toStdString());
	std::cout << "seidng data to server" << std::endl;
	sendMessage(m_serverSocket, &m_outCounter, messageType, messageSent, m_aesKey);
	std::cout << "waiting for response" << std::endl;
	m_serverSocket->waitForReadyRead();

	QString messageRec;
	parseMessage(m_serverSocket, &m_inCounter, &messageType, &messageRec, m_aesKey);

	std::cout << "log in ";
	std::cout << messageRec.toStdString() << std::endl;

	if (messageType == MESSAGETYPE_LOGIN_SUCCESS)
	{
		std::cout << "successful" << std::endl;
		m_isLoggedIn = true;
		return true;
	}
	else if (messageType == MESSAGETYPE_LOGIN_FAIL)
	{
		std::cout << "failed" << std::endl;
	}
	else
	{
		std::cout << "failed with incoming unknown message: " << messageType << " " << messageRec.toStdString() << std::endl;
	}
	return false;
}

bool ClientManager::isLoggedIn() const {
	return m_isLoggedIn;
}

void ClientManager::logOut() {
	quint8 messageType = MESSAGETYPE_LOGOUT;
	QString messageSent = "";
	std::cout << "seidng data to server" << std::endl;
	sendMessage(m_serverSocket, &m_outCounter, messageType, messageSent, m_aesKey);
	std::cout << "you are now logged off" << std::endl;
	m_isLoggedIn = false;
}

void ClientManager::getOnlineUsers() {
	quint8 messageType = MESSAGETYPE_GET_ONLINE_USERS;
	QString messageSent = "";
	std::cout << "seidng data to server" << std::endl;
	sendMessage(m_serverSocket, &m_outCounter, messageType, messageSent, m_aesKey);
	std::cout << "waiting for response" << std::endl;
	m_serverSocket->waitForReadyRead();

	QString messageRec;
	parseMessage(m_serverSocket, &m_inCounter, &messageType, &messageRec, m_aesKey);

	if (messageType != MESSAGETYPE_GET_ONLINE_USERS)
	{
		std::cerr << "Error while getting all online users" << std::endl;
	}
	else
	{
		QStringList users = messageRec.split("|#|");
		std::cout << "Online users:" << std::endl;
		std::cout << "---------" << std::endl;
		for (QString user : users)
		{
			std::cout << user.toStdString() << std::endl;
		}
		std::cout << "---------" << std::endl;
	}
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
