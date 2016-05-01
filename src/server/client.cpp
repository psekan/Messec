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
#include "crypto.h"

Client::Client(qintptr socket, QObject *parent) : QThread(parent), sock_ptr(socket), m_userName(""), m_isLoggedIn(false), readyToCommuinicate(true), m_inCounter(0), m_outCounter(0) {

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

	std::cout << "sending RSA" << std::endl;
	socket->write(reinterpret_cast<char*>(output_buf));
	socket->waitForBytesWritten();
	std::cout << "RSA sent" << std::endl;
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
		std::cout << "rsa decryption failed, length of input is: " << length << " result is: " << result << std::endl;
		//return;
	}
	std::cout << "g";
	memcpy(m_aesKey, output, 32);
	memcpy(&m_clientPort, output + 32, 2);

	if (result != 0)
	{
		std::cout << "keys wasnt distributed correctly" << std::endl;
		//return;
	}
	std::cout << "recieved aes key: ";
	std::cout.write(reinterpret_cast<char*>(m_aesKey), 32);
	std::cout << std::endl;

	std::cout << "recieved port: " << m_clientPort << std::endl;

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
}

void Client::readData()
{
	std::cout << "Reading data" << std::endl;
	ServerManager *server = reinterpret_cast<ServerManager*>(parent());

	quint8 messageType;
	QString message;
	parseMessage(socket, &m_inCounter, &messageType, &message, m_aesKey);
	QStringList list;
	const unsigned char* uMessage;

	QString userName, userPassword;
	switch (messageType) {
	case MESSAGETYPE_LOGIN:
		std::cout << "login initialized" << std::endl;
		list = message.split("|#|");
		server->clientLogIn(list[0], list[1], this);
		std::cout << "login end" << std::endl;
		break;
	case MESSAGETYPE_SIGNIN:
		std::cout << "singin initialized" << std::endl;
		list = message.split("|#|");
		server->clientSignIn(list[0], list[1], this);
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
	/*case MESSAGETYPE_SEND_PORT:
		uMessage = reinterpret_cast<const unsigned char*>(message.toStdString().c_str());
		memcpy(&m_clientPort, uMessage, 2);
		std::cout << "setting client port: " << message.toStdString() << std::endl;
		std::cout << "client port is " << m_clientPort << std::endl;
		std::cout << "setting client port end" << std::endl;
		//std::cout << "2 unsigned chars recieved: ";
		//std::cout.write(reinterpret_cast<const char*>(uMessage), 2) << std::endl;
		break;*/
	case MESSAGETYPE_GET_PARTNER:
		server->createCommunication(this, message);
		break;
	case MESSAGETYPE_CHAT_END:
		readyToCommuinicate = true;
	default:
		std::cout << "Wrong message type" << std::endl;
	}
}

void Client::quit()
{
	exit(0);
}