//
// Created by Peter on 13.03.2016.
//

#include "client.h"
#include "messageTypes.h"
#include <QtGlobal>
#include <QStringList>
#include <QDataStream>
#include <QHostAddress>
#include <iostream>
#include <mbedtls/pk.h>
#include "serverManager.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include "crypto.h"

Client::Client(qintptr socket, QObject *parent) : QThread(parent), sock_ptr(socket), m_userName(""), m_isLoggedIn(false), m_inCounter(0), m_outCounter(0) {

}

void Client::sendRSA()
{
	ServerManager *server = reinterpret_cast<ServerManager*>(parent());

	unsigned char output_buf[32000];

	mbedtls_pk_context rsaKey = server->getRSAKey();
	int result = mbedtls_pk_write_pubkey_pem(&rsaKey, output_buf, 32000);
	if (result != 0)
	{
		qDebug() << "parsing failed";
		return;
	}

	qDebug() << "sending RSA";
	socket->write(reinterpret_cast<char*>(output_buf));
	socket->waitForBytesWritten();
	qDebug() << "RSA sent";
}

void Client::setAES()
{
	socket->waitForReadyRead();
	int result = 0;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *personalization = "desifrovanie_za_pomoci_RSA";
	size_t length_decrypted = 0;
	unsigned char input[512];
	unsigned char output[512];
	ServerManager *server = reinterpret_cast<ServerManager*>(parent());
	mbedtls_pk_context rsaKey = server->getRSAKey();

	initRandomContexts(entropy, ctr_drbg);
	result += mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		reinterpret_cast<const unsigned char *>(personalization), strlen(personalization));

	QDataStream str(socket);
	str.readRawData(reinterpret_cast<char*>(input), 512);

	qDebug() << "decrypting aes key";

	result += mbedtls_pk_decrypt(&rsaKey, input, 512, output, &length_decrypted, 512, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (result != 0)
	{
		qDebug() << "rsa decryption failed, length of input is: " << 512 << " result is: " << result;
		return;
	}
	memcpy(m_aesKey, output, 32);
	memcpy(&m_clientPort, output + 32, 2);

	if (result != 0)
	{
		qDebug() << "keys were not distributed correctly";
		return;
	}
	qDebug() << "received aes key: ";
	std::cout.write(reinterpret_cast<char*>(m_aesKey), 32);
	std::cout << std::endl;

	qDebug() << "received port: " << m_clientPort;

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

bool Client::sendMessage(quint8 messageType, QString message)
{
	return::sendMessage(socket, &m_outCounter, messageType, message, m_aesKey);
}

void Client::logInUser(std::string userName) {
	m_isLoggedIn = true;
	m_userName = userName;
}

void Client::logOutUser() {
	m_isLoggedIn = false;
	m_userName = "";
}

void Client::readData()
{
	qDebug() << "Reading data";
	ServerManager *server = reinterpret_cast<ServerManager*>(parent());

	quint8 messageType;
	QString message;
	parseMessage(socket, &m_inCounter, &messageType, &message, m_aesKey);
	QStringList list;

	QString userName, userPassword;
	switch (messageType) {
	case MESSAGETYPE_LOGIN:
		list = message.split("|#|");
		server->clientLogIn(list[0], list[1], this);
		break;
	case MESSAGETYPE_SIGNIN:
		list = message.split("|#|");
		server->clientSignIn(list[0], list[1], this);
		break;
	case MESSAGETYPE_LOGOUT:
		logOutUser();
		break;
	case MESSAGETYPE_GET_ONLINE_USERS:
		server->getOnlineUsers(this);
		break;
	
	case MESSAGETYPE_GET_PARTNER:
		server->createCommunication(this, message);
		break;
	default:
		qDebug() << "Wrong message type";
	}
}

void Client::quit()
{
	exit(0);
}