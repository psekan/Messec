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

	std::cout << "If you do not trust this key, close connection." << std::endl;

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

	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	str.writeRawData(reinterpret_cast<char*>(output), 512);
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();

	mbedtls_pk_free(&rsa_key);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);

	if (result != 0)
	{
		std::cout << "keys were not distributed correctly" << std::endl;
		return false;
	}

	return true;
}

ClientManager::ClientManager(QObject *parent) : QTcpServer(parent), m_isLoggedIn(false), m_isConnected(false), m_serverSocket(nullptr), m_isChatting(false) {}

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
	}
}


void ClientManager::serverConnect(QString ip, quint16 port) {
	m_serverSocket = new QTcpSocket(this);
	QHostAddress addr(ip);
	m_serverSocket->connectToHost(addr, port);
	if (!m_serverSocket->waitForConnected()) {
		std::cerr << "Could not connect to " << ip.toStdString() << ", " << port << std::endl;
		return;
	}

	if (handleKeyDistribution()) {
		m_isConnected = true;
		m_outCounter = 0;
		m_inCounter = 0;
		std::cout << "Successfully connected" << std::endl;
		return;
	}
	std::cout << "Could not connect" << std::endl;
	return;
}

void ClientManager::disconnect() {
	if (m_serverSocket != nullptr)
	{
		if (isChatting())
			chatEnd();
		m_isLoggedIn = false;
		m_isConnected = false;
		m_serverSocket->disconnectFromHost();
		delete m_serverSocket;
		m_serverSocket = nullptr;
	}
}

void ClientManager::signIn(QString userName, QString password) {
	if (password.length() < 8) {
		std::cout << "Password has to be at least 8 characters long" << std::endl;
		return;
	}
	quint8 messageType = MESSAGETYPE_SIGNIN;
	QString messageSent = QString::fromStdString(userName.toStdString()) + "|#|" + QString::fromStdString(password.toStdString());
	sendMessage(m_serverSocket, &m_outCounter, messageType, messageSent, m_aesKey);
	m_serverSocket->waitForReadyRead();

	QString messageRec;
	parseMessage(m_serverSocket, &m_inCounter, &messageType, &messageRec, m_aesKey);

	std::cout << "sign in ";

	if (messageType == MESSAGETYPE_SIGNIN_SUCCESS)
	{
		std::cout << "successful" << std::endl;
		m_isLoggedIn = true;
		m_myName = userName.toStdString();
		return;
	}
	else if (messageType == MESSAGETYPE_SIGNIN_FAIL)
	{
		std::cout << "failed" << std::endl;
	}
	else
	{
		std::cout << "failed with incoming unknown message: " << messageType << messageRec.toStdString() << std::endl;
	}
	return;
}

void ClientManager::logIn(QString userName, QString password) {
	quint8 messageType = MESSAGETYPE_LOGIN;
	QString messageSent = userName + "|#|" + password;
	sendMessage(m_serverSocket, &m_outCounter, messageType, messageSent, m_aesKey);
	m_serverSocket->waitForReadyRead();

	QString messageRec;
	parseMessage(m_serverSocket, &m_inCounter, &messageType, &messageRec, m_aesKey);

	std::cout << "log in ";

	if (messageType == MESSAGETYPE_LOGIN_SUCCESS)
	{
		std::cout << "successful" << std::endl;
		m_isLoggedIn = true;
		m_myName = userName.toStdString();
		return;
	}
	else if (messageType == MESSAGETYPE_LOGIN_FAIL)
	{
		std::cout << "failed" << std::endl;
	}
	else
	{
		std::cout << "failed with incoming unknown message: " << messageType << " " << messageRec.toStdString() << std::endl;
	}
	return;
}

void ClientManager::logOut() {
	quint8 messageType = MESSAGETYPE_LOGOUT;
	QString messageSent = "";
	sendMessage(m_serverSocket, &m_outCounter, messageType, messageSent, m_aesKey);
	m_isLoggedIn = false;
	m_myName = "";
	std::cout << "you are now logged out" << std::endl;
	if (isChatting())
		chatEnd();
}

void ClientManager::getOnlineUsers() {
	quint8 messageType = MESSAGETYPE_GET_ONLINE_USERS;
	QString messageSent = "";
	sendMessage(m_serverSocket, &m_outCounter, messageType, messageSent, m_aesKey);
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
	auto it = std::find(m_messengers.begin(), m_messengers.end(), msngr);
	m_messengers.erase(it);
	delete msngr;
	m_isChatting = false;
	std::cout << "Chat closed" << std::endl;
}

void ClientManager::startCommunicationWith(QString userName) {
	if (m_myName == userName.toStdString()) {
		std::cout << "You dont need chat to talk with yourself" << std::endl;
		return;
	}

	quint8 messageType = MESSAGETYPE_GET_PARTNER;
	sendMessage(m_serverSocket, &m_outCounter, messageType, userName, m_aesKey);

	uint32_t responseLenght;
	unsigned char responseLenghtAndTag[20];
	QDataStream response(m_serverSocket);
	m_serverSocket->waitForReadyRead();
	unsigned char responseTag[16];
	
	response.readRawData(reinterpret_cast<char*>(responseLenghtAndTag), 20);
	
	if(!decryptLength(responseLenght, responseLenghtAndTag, responseLenghtAndTag + 4, &m_inCounter, m_aesKey))
	{
		std::cout << "decrypt of lenght failed" << std::endl;
		return;
	}	
	unsigned char *uResponse = new unsigned char[responseLenght];
	response.readRawData(reinterpret_cast<char*>(responseTag), 16);
	response.readRawData(reinterpret_cast<char*>(uResponse), responseLenght);
	
	const unsigned char *decryptedResponse = decryptMessage(&messageType, &m_inCounter, uResponse, responseLenght, responseTag, m_aesKey);
	responseLenght -= sizeof(quint8); // - messagetype

	if(decryptedResponse == nullptr)
	{
		std::cout << "decrypt of message failed" << std::endl;
		return;
	}

	if (messageType == MESSAGETYPE_PARTNER_INFO)
	{
		uint32_t lenghtForB;
		std::string ipString = std::string(reinterpret_cast<const char *>(decryptedResponse + 64 + 4), responseLenght - 64 - 4 - 4);

		QString ip = QString::fromStdString(ipString);
		quint16 port;
		unsigned char randomNumbers[64];
		memcpy(&port, decryptedResponse + 64, 4);
		memcpy(&lenghtForB, decryptedResponse + responseLenght - 4, 4);
		memcpy(randomNumbers, decryptedResponse, 64);

		unsigned char *dataToB = new unsigned char[lenghtForB];
		response.readRawData(reinterpret_cast<char*>(dataToB), lenghtForB);
		// message should be send by messenger to client B, here is deleted because next parts of protocol arent implemented yet
		delete[] uResponse;
		delete[] (decryptedResponse - sizeof(quint8));

		Messenger* msngr = new Messenger(ip, port, dataToB, lenghtForB, randomNumbers, this);
		runMessenger(msngr, false);
	}
	else if (messageType == MESSAGETYPE_PARTNER_NOT_ONLINE) {
		std::cout << "Partner is not online" << std::endl;
	}
	else
		std::cout << "Incoming unknown messagetype: " << messageType << std::endl;
}

void ClientManager::incomingConnection(qintptr handle)
{
	if (isChatting()) {
		QTcpSocket* eraseSocket  = new QTcpSocket(this);
		eraseSocket->setSocketDescriptor(handle);
		eraseSocket->disconnect();
		delete eraseSocket;
	}
	else {
		Messenger* mes = new Messenger(handle, this, m_aesKey);
		runMessenger(mes, true);
	}
}

void ClientManager::runMessenger(Messenger* msngr, bool isServer) {
	msngr->m_isAlive = (isServer ? msngr->serverHandshake() : msngr->clientHandshake());

	connect(msngr, SIGNAL(finished()), this, SLOT(deleteMessenger()));
	connect(this, SIGNAL(sendMsgSignal(QString)), msngr, SLOT(sendEncrypted(QString)));
	connect(this, SIGNAL(sendFile(QString)), msngr, SLOT(sendFile(QString)));
	connect(this, SIGNAL(disconnectClientSignal()), msngr, SLOT(quitMessenger()));
	msngr->start();
	m_messengers.push_back(msngr);
	if (msngr->isAlive()) {
		m_isChatting = true;
		std::cout << "Connection is ready" << std::endl;
	}
	else {
		std::cout << "Connection failed" << std::endl;
		chatEnd();
	}
}

void ClientManager::sendToMessenger(QString msg) {
	emit sendMsgSignal(msg);
}

void ClientManager::sendFileSlot(QString msg)
{
	emit sendFile(msg);
}

void ClientManager::chatEnd(){	
	emit disconnectClientSignal();
}
