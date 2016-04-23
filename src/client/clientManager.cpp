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

void ClientManager::signIn(QString userName, QString password) {
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

	QDataStream u(m_serverSocket);
	QString message;
	u >> messageType;
	u >> message;
	
	std::cout << "response is: " << std::endl;
	
	if(messageType == MESSAGETYPE_SIGNIN_SUCCESS)
	{
		std::cout << "succes" << std::endl;
	}
	else if(messageType == MESSAGETYPE_SIGNIN_FAIL)
	{
		std::cout << "failure" << std::endl;
	}
	else
	{
		std::cout << "WTF?!!!: toto prislo " << messageType << " " << message.toStdString() << std::endl;
	}

	emit signInResult(messageType == MESSAGETYPE_SIGNIN_SUCCESS);
}

void ClientManager::logIn(QString userName, QString password) {
	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_LOGIN;
	str << messageType;
	str << QString::fromStdString(userName.toStdString());
	str << QString::fromStdString(password.toStdString());
	std::cout << "sending data to server" << std::endl;
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();
	std::cout << "waiting for response" << std::endl;
	m_serverSocket->waitForReadyRead();

	QDataStream u(m_serverSocket);
	QString message;
	u >> messageType;
	u >> message;
	
	std::cout << "response is: " << std::endl;
	
	if (messageType == MESSAGETYPE_LOGIN_SUCCESS)
	{
		std::cout << "succes" << std::endl;
	}
	else if(messageType == MESSAGETYPE_LOGIN_FAIL)
	{
		std::cout << "failure" << std::endl;
	}
	else
	{
		std::cout << "WTF?!!!: toto prislo " << messageType << " " << message.toStdString() << std::endl;
	}

	m_isLoggedIn = true;
	emit logInResult(messageType == MESSAGETYPE_LOGIN_SUCCESS);
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

	if (messageType != MESSAGETYPE_GET_ONLINE_USERS)
	{
		std::cerr << "Error while getting all online users" << std::endl;
		emit getOnlineUsersResult(QStringList());
	}

	QStringList users = message.split("|#|");
	emit getOnlineUsersResult(users);
}

std::vector<Messenger*> ClientManager::getMessengers() const {
	return m_messengers;
}

bool ClientManager::startCommunicationWith(std::string userName) {
	//TODO
	return false;
}
