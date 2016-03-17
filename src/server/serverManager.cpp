//
// Created by Peter on 13.03.2016.
//

#include "serverManager.h"

void ServerManager::processClientCommunication(Client* client) {
	//TODO
}

void ServerManager::processNewConnectionRequests() {
	//TODO
}

void ServerManager::sendNewRequestToClient(Client* from, Client* to, unsigned char hash[16]) {
	//TODO
}

void ServerManager::createCommunicationBetween(Client* communicationServer, Client* communicationClient) {
	//TODO
}

ServerManager::ServerManager(std::string dbFilePath) : m_database(dbFilePath, "y3%1!Ko7e@3e&"), m_isRunning(false) {
	//TODO
}

bool ServerManager::start(int port, unsigned keySize) {
	//TODO
	m_isRunning = true;
	return false;
}

void ServerManager::stop() {
	//TODO
	m_isRunning = false;
}

void ServerManager::clearDatabase() {
	//TODO Marek
}

std::vector<std::string> ServerManager::getOnlineUsers() {
	//TODO Marek
	//Prebehni kontajner klientov a vytiahni mena prihlasenych
	std::vector<std::string> sample;
	return sample;
}

void ServerManager::removeUserFromDb(std::string userName) {
	//TODO Marek
}

void ServerManager::kickUser(std::string userName) {
	//TODO Marek
	//clientLogOut a clientDisconnect
}

bool ServerManager::isRunning() const {
	return m_isRunning;
}

bool ServerManager::userRegistration(std::string userName, std::string password) {
	//TODO Marek
	return false;
}

bool ServerManager::userAuthentication(std::string userName, std::string password) {
	//TODO Marek
	//Cisto overenie udajov na db
	return false;
}

Client* ServerManager::clientConnect(unsigned socket) {
	//TODO Marek
	//Pouzivaj triedu Client, vytvor pomocou dynamickej pamate novy object a 
	//hod do kontajneru obsahujuceho pripojenych klientov
	return nullptr;
}

void ServerManager::clientDisconnect(Client* client) {
	//TODO Marek
	//Vymaz z kontajneru, delete object
}

bool ServerManager::clientLogIn(Client* client, std::string userName, std::string password) {
	//TODO Marek
	//Zavolaj userAuthentication a pripadne logInUser na Client
	return false;
}

void ServerManager::clientLogOut(Client* client) {
	//TODO Marek
	//logOutUser na Client
}