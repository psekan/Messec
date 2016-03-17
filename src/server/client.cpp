//
// Created by Peter on 13.03.2016.
//

#include "client.h"

Client::Client(unsigned socket) : m_socket(socket), m_userName(""), m_isLoggedIn(false) {
	
}

Client::~Client() {
	//TODO uzavriet spojenie
}

bool Client::isLoggedIn() const {
	return m_isLoggedIn;
}

IPv4 Client::getIPv4() const {
	//TODO
	return IPv4("0.0.0.0");
}

bool Client::sendMessage(unsigned long long messageLength, unsigned char* message) {
	//TODO
	return false;
}

void Client::logInUser(std::string userName) {
	this->m_isLoggedIn = true;
	this->m_userName = userName;
}

void Client::logOutUser() {
	this->m_isLoggedIn = false;
}
