//
// Created by Peter on 12.03.2016.
//

#include "clientManager.h"
#include <QHostAddress>
#include <cstring>
#include <iostream>
#include <QDataStream>
#include <messageTypes.h>

ClientManager::ClientManager(QObject *parent) : parent(parent){// : QTcpServer(parent) {
	m_isLoggedIn = false;
	m_isConnected = false;
	m_serverSocket = nullptr;
}

ClientManager::~ClientManager() {
	disconnect();
}

bool ClientManager::signalconnect(QString ip, int port) {
	m_serverSocket = new QTcpSocket(parent);
	QHostAddress addr(ip);
	m_serverSocket->connectToHost(addr, port);
	if (!m_serverSocket->waitForConnected()) {
		std::cerr << "Could not connect to " << ip.toStdString() << ", " << addr.toString().toStdString() << std::endl;
		std::cout << "Connect failed" << std::endl;
		return false;
	}
	m_isConnected = true;
	std::cout << "Successfully connected" << std::endl;
	return true;
}

bool ClientManager::isConnected() const {
	return m_isConnected;
}

void ClientManager::disconnect() {
	if (m_serverSocket != nullptr) 
	{
		m_isConnected = false;
		m_serverSocket->disconnectFromHost();
		delete m_serverSocket;
		m_serverSocket = nullptr;
	}
}

bool ClientManager::signIn(QString userName, QString password) {
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
	
	std::cout << "sign in ";	
	if(messageType == MESSAGETYPE_SIGNIN_SUCCESS)
	{
		std::cout << "successful" << std::endl;
		return true;
	}
	else if(messageType == MESSAGETYPE_SIGNIN_FAIL)
	{
		std::cout << "failed" << std::endl;
	}
	else
	{
		std::cout << "failed with incoming unknown message: " << messageType << " " << message.toStdString() << std::endl;
	}
	return false;
}

bool ClientManager::logIn(QString userName, QString password) {
	QByteArray arr;
	QDataStream str(&arr, QIODevice::WriteOnly);
	quint8 messageType = MESSAGETYPE_LOGIN;
	str << messageType;
	str << QString::fromStdString(userName.toStdString());
	str << QString::fromStdString(password.toStdString());
	std::cout << "sending data to server" << std::endl; /////////////////////////debug print
	m_serverSocket->write(arr);
	m_serverSocket->waitForBytesWritten();
	std::cout << "waiting for response" << std::endl; //////////////////////////debug print
	m_serverSocket->waitForReadyRead();

	QDataStream u(m_serverSocket);
	QString message;
	u >> messageType;
	u >> message;
	
	std::cout << "log in ";
	
	if (messageType == MESSAGETYPE_LOGIN_SUCCESS)
	{
		std::cout << "successful" << std::endl;
		m_isLoggedIn = true;
		return true;
	}
	else if(messageType == MESSAGETYPE_LOGIN_FAIL)
	{
		std::cout << "failed" << std::endl;
	}
	else
	{
		std::cout << "failed with incoming unknown message: " << messageType << " " << message.toStdString() << std::endl;
	}
	return false;
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
	}
	else
	{
		QStringList users = message.split("|#|");
		std::cout << "Online users:" << std::endl;
		for (QString user : users)
		{
			std::cout << user.toStdString() << std::endl;
		}
	}
}

std::vector<Messenger*> ClientManager::getMessengers() const {
	return m_messengers;
}

bool ClientManager::startCommunicationWith(std::string userName) {
	//TODO
	return false;
}
