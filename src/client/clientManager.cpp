//
// Created by Peter on 12.03.2016.
//

#include "clientManager.h"

ClientManager::ClientManager(std::function<void(ConnectionErrors)> connectionLostCallback, std::function<void(std::string, bool)> userChangeStatusCallback, std::function<bool(std::string)> newRequestCallback, std::function<void(std::string)> requestRejectedCallback, std::function<void(std::string, Messenger*)> newCommunicationStartedCallback) {
	m_connectionLostCallback = connectionLostCallback;
	m_newCommunicationStartedCallback = newCommunicationStartedCallback;
	m_newRequestCallback = newRequestCallback;
	m_requestRejectedCallback = requestRejectedCallback;
	m_userChangeStatusCallback = userChangeStatusCallback;

	m_isLoggedIn = false;
	m_isConnected = false;
	m_serverSocket = 0;
}

bool ClientManager::connect(std::string ip, int port) {
	//TODO
	return false;
}

bool ClientManager::isConnected() const {
	return m_isConnected;
}

void ClientManager::disconnect() {
	//TODO
}

bool ClientManager::signIn(std::string userName, std::string password) {
	//Message schema: type[1], userNameLenght[1], userName[userNameLenght], passwordLenght[1], password[passwordLenght]
	unsigned char userNameSize = (unsigned char)(userName.size() >= 256 ? 255 : userName.size());
	unsigned char passwordSize = (unsigned char)(password.size() >= 256 ? 255 : password.size());
	unsigned char* message = new unsigned char[3 + userNameSize + passwordSize];
	memcpy(message, &MESSAGE_TYPE_SIGNIN, 1);
	memcpy(message + 1, &userNameSize, 1);
	memcpy(message + 2, userName.c_str(), userNameSize);
	memcpy(message + 2 + userNameSize, &passwordSize, 1);
	memcpy(message + 3 + userNameSize, password.c_str(), passwordSize);
	//TODO send message
	delete[] message;
	return false;
}

bool ClientManager::logIn(std::string userName, std::string password) {
	//Message schema: type[1], userNameLenght[1], userName[userNameLenght], passwordLenght[1], password[passwordLenght]
	unsigned char userNameSize = (unsigned char)(userName.size() >= 256 ? 255 : userName.size());
	unsigned char passwordSize = (unsigned char)(password.size() >= 256 ? 255 : password.size());
	unsigned char* message = new unsigned char[3 + userNameSize + passwordSize];
	memcpy(message, &MESSAGE_TYPE_LOGIN, 1);
	memcpy(message + 1, &userNameSize, 1);
	memcpy(message + 2, userName.c_str(), userNameSize);
	memcpy(message + 2 + userNameSize, &passwordSize, 1);
	memcpy(message + 3 + userNameSize, password.c_str(), passwordSize);
	//TODO send message
	delete[] message;
	return false;
}

bool ClientManager::isLoggedIn() const {
	return m_isLoggedIn;
}

void ClientManager::logOut() {
	//Message schema: type[1]
	unsigned char* message = new unsigned char[1];
	memcpy(message, &MESSAGE_TYPE_LOGOUT, 1);
	//TODO send message
	delete[] message;
}

std::vector<std::string> ClientManager::getOnlineUsers() const {
	return m_onlineUsers;
}

std::vector<Messenger*> ClientManager::getMessengers() const {
	return m_messengers;
}

bool ClientManager::startCommunicationWith(std::string userName) {
	//TODO
	return false;
}
