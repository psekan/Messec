//
// Created by Peter on 13.03.2016.
//

#include "client.h"
#include "messageTypes.h"
#include <QtGlobal>
#include <QDataStream>
#include <QHostAddress>
#include <iostream>
#include <mbedtls/pk.h>
#include "serverManager.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

Client::Client(qintptr socket, QObject *parent) : QThread(parent), sock_ptr(socket), m_userName(""), m_isLoggedIn(false), readyToCommuinicate(true) {
	
}

void Client::sendRSA()
{
	ServerManager *server = reinterpret_cast<ServerManager*>(parent());

	unsigned char output_buf[32000];

	mbedtls_pk_context rsaKey = server->getRSAKey();
	int result = mbedtls_pk_write_pubkey_pem(&rsaKey, output_buf, 32000);
	if (result != 0)
	{
		std::cout << "parsing failed";
		return;
	}

	socket->write(reinterpret_cast<char*>(output_buf));
	socket->waitForBytesWritten();
}

void Client::setAES()
{
	socket->waitForReadyRead();
	int result = 0;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *personalization = "desifrovanie_za_pomoci_RSA";
	size_t length = 0;
	size_t length_decrypted = 0;
	unsigned char input[512];
	unsigned char output[512];
	ServerManager *server = reinterpret_cast<ServerManager*>(parent());
	mbedtls_pk_context rsaKey = server->getRSAKey();
	
	initRandomContexts(entropy, ctr_drbg);
	result += mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		reinterpret_cast<const unsigned char *>(personalization), strlen(personalization));

	QDataStream str(socket);
	str >> length;
	str.readRawData(reinterpret_cast<char*>(input), length);

	std::cout << "decrypting aes key" << std::endl;

	result += mbedtls_pk_decrypt(&rsaKey, input, length, output, &length_decrypted, 512, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (result != 0)
	{
		std::cout << "rsa decryption failed, length of input is: " << length << " result is: "<< result << std::endl;
		//return;
	}

	memcpy(m_aesKey, output, 32);

	if (result != 0)
	{
		std::cout << "keys wasnt distributed correctly" << std::endl;
		return;
	}

	std::cout << "recieved aes key: ";
	std::cout.write(reinterpret_cast<char*>(m_aesKey), 32);
	std::cout << std::endl;
	
	mbedtls_pk_free(&rsaKey);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);

}

void Client::run() {
	socket = new QTcpSocket(NULL);
	socket->setSocketDescriptor(sock_ptr);
	std::cout << "distributing keys" << std::endl;
	sendRSA();
	setAES();
	connect(this, SIGNAL(finished()), this, SLOT(deleteLater()), Qt::DirectConnection);
	connect(parent(), SIGNAL(finished()), this, SLOT(quit()), Qt::DirectConnection);
	connect(socket, SIGNAL(readyRead()), this, SLOT(readData()), Qt::DirectConnection);
	connect(socket, SIGNAL(disconnected()), this, SLOT(quit()), Qt::DirectConnection);
	const QHostAddress &connected = socket->peerAddress();
	qDebug() << connected.toString();
	exec();
}

Client::~Client() {
	delete socket;
}

bool Client::isLoggedIn() const {
	return m_isLoggedIn;
}

IPv4 Client::getIPv4() const {
	return IPv4(socket->peerAddress().toString().toStdString());
}

bool Client::sendMessage(quint8 messageType, QString message) {
	QByteArray array;
	QDataStream output(&array, QIODevice::WriteOnly);

	//TODO encrypt
	output << messageType;
	output << message;

	socket->write(array);
	return true;
}

void Client::logInUser(std::string userName) {
	m_isLoggedIn = true;
	m_userName = userName;
}

void Client::logOutUser() {
	m_isLoggedIn = false;
}

void Client::readData()
{
	std::cout << "Reading data" << std::endl;
	QDataStream input(socket);

	ServerManager *server = reinterpret_cast<ServerManager*>(parent());

	quint8 messageType;
	//TODO decrypt
	input >> messageType;

	QString userName, userPassword;
	switch (messageType) {
	case MESSAGETYPE_LOGIN:
		std::cout << "login initialized" << std::endl;
		input >> userName >> userPassword;
		server->clientLogIn(userName, userPassword, this);
		std::cout << "login end" << std::endl;
		break;
	case MESSAGETYPE_SIGNIN:
		std::cout << "singin initialized" << std::endl;
		input >> userName >> userPassword;
		server->clientSignIn(userName, userPassword, this);
		std::cout << "signin end" << std::endl;
		break;
	case MESSAGETYPE_LOGOUT:
		std::cout << "logout initialized" << std::endl;
		logOutUser();
		std::cout << "logout end" << std::endl;
		break;
	case MESSAGETYPE_GET_ONLINE_USERS:
		std::cout << "listing of users initialized" << std::endl;
		server->getOnlineUsers(this);
		std::cout << "listing of users end" << std::endl;
		break;
	case MESSAGETYPE_SEND_PORT:
		std::cout << "setting client port" << std::endl;
		quint16 port;
		input >> port;
		setClientPort(port);
		std::cout << "client port is " << getClientPort() << std::endl;
		std::cout << "setting client port end" << std::endl;
		break;
	case MESSAGETYPE_GET_PARTNER:
		input >> userName;
		server->createCommunication(this, userName);

		break;
	default:
		std::cout << "Wrong message type" << std::endl;
	}
}

void Client::quit()
{
	exit(0);
}