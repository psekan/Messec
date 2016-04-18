//
// Created by Peter on 13.03.2016.
//

#include "client.h"
#include "messageTypes.h"
#include <QDataStream>
#include <QHostAddress>

Client::Client(qintptr socket, QObject *parent) : QThread(parent), sock_ptr(socket), m_userName(""), m_isLoggedIn(false) {
	
}

void Client::run() {
	socket = new QTcpSocket(NULL);
	socket->setSocketDescriptor(sock_ptr);
	connect(this, SIGNAL(finished()), this, SLOT(deleteLater()), Qt::DirectConnection);
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
	this->m_isLoggedIn = true;
	this->m_userName = userName;
}

void Client::logOutUser() {
	this->m_isLoggedIn = false;
}

void Client::readData()
{
	qDebug() << "Reading data";
	QDataStream input(socket);

	quint8 messageType;
	//TODO decrypt
	input >> messageType;

	QString userName, userPassword;
	switch (messageType) {
	case MESSAGETYPE_LOGIN:
		input >> userName >> userPassword;
		emit logIn(userName.toStdString(), userPassword.toStdString());
		break;
	case MESSAGETYPE_SIGNIN:
		input >> userName >> userPassword;
		emit signIn(userName.toStdString(), userPassword.toStdString());
		break;
	case MESSAGETYPE_LOGOUT:
		emit logOut();
		break;
	case MESSAGETYPE_GET_ONLINE_USERS:
		emit getOnlineUsers();
		break;
	default:
		qDebug() << "Wrong message type";
	}
}

void Client::quit()
{
	emit disconnect();
	exit(0);
}