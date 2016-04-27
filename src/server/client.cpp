//
// Created by Peter on 13.03.2016.
//

#include "client.h"
#include "messageTypes.h"
#include <QtGlobal>
#include <QDataStream>
#include <QHostAddress>
#include <iostream>
#include <serverManager.h>

Client::Client(qintptr socket, QObject *parent) : QThread(parent), sock_ptr(socket), m_userName(""), m_isLoggedIn(false), readyToCommuinicate(true) {
	
}

void Client::run() {
	socket = new QTcpSocket(NULL);
	socket->setSocketDescriptor(sock_ptr);
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