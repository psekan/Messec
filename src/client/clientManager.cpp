//
// Created by Peter on 12.03.2016.
//

#include "clientManager.h"
#include <QHostAddress>
#include <cstring>
#include <iostream>
#include <QDataStream>
#include <messageTypes.h>

/*ClientManager::ClientManager(std::function<void(ConnectionErrors)> connectionLostCallback, std::function<void(std::string, bool)> userChangeStatusCallback, std::function<bool(std::string)> newRequestCallback, std::function<void(std::string)> requestRejectedCallback, std::function<void(std::string, Messenger*)> newCommunicationStartedCallback) {
	m_connectionLostCallback = connectionLostCallback;
	m_newCommunicationStartedCallback = newCommunicationStartedCallback;
	m_newRequestCallback = newRequestCallback;
	m_requestRejectedCallback = requestRejectedCallback;
	m_userChangeStatusCallback = userChangeStatusCallback;

	m_isLoggedIn = false;
	m_isConnected = false;
	m_serverSocket = 0;
}*/

ClientManager::ClientManager(QObject *parent) : QThread(parent) {
	m_isLoggedIn = false;
	m_isConnected = false;
	m_serverSocket = nullptr;
}

ClientManager::~ClientManager() {
	if (m_serverSocket != nullptr) {
		m_serverSocket->disconnectFromHost();
		delete m_serverSocket;
	}
}

void ClientManager::run() {
	exec();
}


void ClientManager::signalconnect(QString ip, int port) {
	m_serverSocket = new QTcpSocket(this);
	QHostAddress addr(ip);
	m_serverSocket->connectToHost(addr, port);
	if (!m_serverSocket->waitForConnected()) {
		std::cerr << "Could not connect to " << ip.toStdString() << ", " << addr.toString().toStdString() << std::endl;
		emit signalconnected(false);
		return;
	}
	m_isConnected = true;
	emit signalconnected(true);
	return;
}

bool ClientManager::isConnected() const {
	return m_isConnected;
}

void ClientManager::disconnect() {
	m_isConnected = true;
	m_serverSocket->disconnectFromHost();
	delete m_serverSocket;
	m_serverSocket = nullptr;
}

bool ClientManager::signIn(std::string userName, std::string password) {
	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_SIGNIN;
	str << messageType;
	str << QString::fromStdString(userName);
	str << QString::fromStdString(password);
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();
	m_serverSocket->waitForReadyRead();

	QDataStream u(m_serverSocket);
	QString message;
	u >> messageType;
	u >> message;

	return (messageType == MESSAGETYPE_SIGNIN_SUCCESS);
}

bool ClientManager::logIn(std::string userName, std::string password) {
	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_LOGIN;
	str << messageType;
	str << QString::fromStdString(userName);
	str << QString::fromStdString(password);
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();
	m_serverSocket->waitForReadyRead();

	QDataStream u(m_serverSocket);
	QString message;
	u >> messageType;
	u >> message;

	return (messageType == MESSAGETYPE_LOGIN_SUCCESS);
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
}

std::vector<std::string> ClientManager::getOnlineUsers() const {
	//return m_onlineUsers;

	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_GET_ONLINE_USERS;
	str << messageType;
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();
	m_serverSocket->waitForReadyRead();

	QDataStream u(m_serverSocket);
	QString message;
	u >> messageType;
	u >> message;

	std::vector<std::string> users;
	if (messageType == MESSAGETYPE_GET_ONLINE_USERS)
	{
		std::cerr << "Error while getting all online users" << std::endl;
		return users;
	}

	size_t pos = 0;
	QStringList list = message.split("|#|");
	for (QString user : list)
	{
		users.push_back(user.toStdString());
	}
	return users;
}

std::vector<Messenger*> ClientManager::getMessengers() const {
	return m_messengers;
}

bool ClientManager::startCommunicationWith(std::string userName) {
	//TODO
	return false;
}
