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
	str << quint64(length);
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

ClientManager::ClientManager() : m_isLoggedIn(false), m_isConnected(false), m_serverSocket(nullptr), QTcpServer(0), m_isChatting(false) {}

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
		connect(this, SIGNAL(newConnection()), this, SLOT(connectionAvailable()));
	}
}


bool ClientManager::serverConnect(QString ip, quint16 port) {
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

void ClientManager::disconnect() {
	if (m_serverSocket != nullptr)
	{
		m_isLoggedIn = false;
		m_isConnected = false;
		m_serverSocket->disconnectFromHost();
		delete m_serverSocket;
		m_serverSocket = nullptr;
		m_isChatting = false;
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
	std::cout << "sending data to server" << std::endl;
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
	m_isChatting = false;
	quint8 messageType = MESSAGETYPE_CHAT_END;
	QString messageSent = "";
	std::cout << "chat end" << std::endl;
	sendMessage(m_serverSocket, &m_outCounter, messageType, messageSent, m_aesKey);
}

bool ClientManager::startCommunicationWith(QString userName) {
	quint8 messageType = MESSAGETYPE_GET_PARTNER;
	sendMessage(m_serverSocket, &m_outCounter, messageType, userName, m_aesKey);

	m_serverSocket->waitForReadyRead();
	QDataStream response(m_serverSocket);
	response >> messageType;
	if (messageType == MESSAGETYPE_PARTNER_INFO)
	{
		std::cout << "Got response from server" << std::endl;
		QString ip;
		quint16 port;
		response >> port >> ip;
		std::cout << "port: " << port << " ip: " << ip.toStdString() << std::endl; //////////////// debug print
		Messenger* msngr = new Messenger(ip, port, userName, this);
		msngr->start();
		connect(msngr, SIGNAL(finished()), this, SLOT(deleteMessenger()));
		connect(this, SIGNAL(sendMsgSignal(QString)), msngr, SLOT(sendNotCrypted(QString)));
		connect(this, SIGNAL(disconnectClientSignal()), msngr, SLOT(quitMessenger()));
		//connect(parent(), SIGNAL(finished()), msngr, SLOT(quit()), Qt::DirectConnection);
		m_messengers.push_back(msngr);
		std::cout << "Connection with " << userName.toStdString() << " is ready" << std::endl;
		m_isChatting = true;
		return true;
	}
	else if (messageType == MESSAGETYPE_PARTNER_NOT_READY)
		std::cout << "User " << userName.toStdString() << " is not ready for communication" << std::endl;
	else
		std::cout << "Incoming unknown messagetype: " << messageType << std::endl;
	return false;
}


void ClientManager::incomingConnection(qintptr handle)
{
	std::cout << "Incoming connection " << std::endl;///////////////////////debug print
	Messenger* mes = new Messenger(handle, this);
	mes->start();
	connect(mes, SIGNAL(finished()), this, SLOT(deleteMessenger()));
	connect(this, SIGNAL(finished()), mes, SLOT(quit()), Qt::DirectConnection);
	connect(this, SIGNAL(sendMsgSignal(QString)), mes, SLOT(sendNotCrypted(QString)));
	connect(this, SIGNAL(disconnectClientSignal()), mes, SLOT(quitMessenger()));
	m_messengers.push_back(mes);
	m_isChatting = true;
}

void ClientManager::sendToMessenger(QString msg) {
	emit sendMsgSignal(msg);
}

void ClientManager::chatEnd(){	
	emit disconnectClientSignal();
}

void ClientManager::connectionAvailable() {
	std::cout << "signal emitted Incoming connection " << std::endl;///////////////////////debug print

}

