//
// Created by Peter on 13.03.2016.
//

#include "serverManager.h"
#include <iostream>
#include <algorithm>
#include "mbedtls/havege.h"
#include "mbedtls/sha512.h"

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

}

bool ServerManager::start(int port, unsigned keySize) {
	//TODO
	m_isRunning = true;
	return true;
}

void ServerManager::stop() {
	//TODO
	m_isRunning = false;
}

void ServerManager::clearDatabase() {
	//TODO Marek
	m_database.clearDatabase();
}

std::vector<std::string> ServerManager::getOnlineUsers() {
	//TODO Marek
	//Prebehni kontajner klientov a vytiahni mena prihlasenych

	std::vector<std::string> onlineClients;

	for (auto it = m_clients.begin(); it != m_clients.end(); ++it)
	{
		if ((*it)->isLoggedIn())
		{
			onlineClients.push_back((*it)->m_userName);
		}
	}

	return onlineClients;
}

void ServerManager::removeUserFromDb(std::string userName) {
	//TODO Marek
	if (!m_database.removeUser(userName))
	{
		std::cerr << "Client remove from database failed";
	}
}

void ServerManager::kickUser(std::string userName) {
	//TODO Marek
	//clientLogOut a clientDisconnect
	std::string message = "You were kicked by server";

	for (auto it = m_clients.begin(); it < m_clients.end(); ++it)
	{
		if (userName.compare((*it)->m_userName) == 0)
		{
			(*it)->sendMessage(message.length(), reinterpret_cast<const unsigned char*>(message.c_str()));
			clientLogOut(*it);
			clientDisconnect(*it);
			return;
		}
	}
}

bool ServerManager::isRunning() const {
	return m_isRunning;
}

bool ServerManager::userRegistration(std::string userName, std::string password) {
	//TODO Marek
	
	unsigned char salt[512];
	mbedtls_sha512_context sha_ctx;
	unsigned char sha_output[64];
	mbedtls_havege_state havege_st;
	
	mbedtls_havege_init(&havege_st);
	mbedtls_havege_random(&havege_st, salt, 512);
	
	std::string salt_string(reinterpret_cast<char*>(salt));
	password += salt_string;
	
	mbedtls_sha512_init(&sha_ctx);
	mbedtls_sha512_starts(&sha_ctx, 0);
	mbedtls_sha512_update(&sha_ctx, reinterpret_cast<const unsigned char*>(password.c_str()), password.length());
	mbedtls_sha512_finish(&sha_ctx, sha_output);

	std::string hash(reinterpret_cast<char*>(sha_output));
	
	return m_database.insertUser(UserDatabaseRow(userName, hash, salt_string));
}

bool ServerManager::userAuthentication(std::string userName, std::string password) {
	//TODO Marek
	//Cisto overenie udajov na db

	UserDatabaseRow row = m_database.getUser(userName);
	std::string salt = row.getSalt();
	std::string row_hash = row.getPassword();

	mbedtls_sha512_context sha_ctx;
	unsigned char sha_output[64];

	password += salt;

	mbedtls_sha512_init(&sha_ctx);
	mbedtls_sha512_starts(&sha_ctx, 0);
	mbedtls_sha512_update(&sha_ctx, reinterpret_cast<const unsigned char*>(password.c_str()), password.length());
	mbedtls_sha512_finish(&sha_ctx, sha_output);

	std::string hash(reinterpret_cast<char*>(sha_output));

	if (row_hash.compare(hash) == 0)
	{
		return true;
	}

	return false;
}

Client* ServerManager::clientConnect(unsigned socket) {
	//TODO Marek
	//Pouzivaj triedu Client, vytvor pomocou dynamickej pamate novy object a 
	//hod do kontajneru obsahujuceho pripojenych klientov

	Client* newClient = new Client(socket);
	m_clients.push_back(newClient);
	return newClient;
}

void ServerManager::clientDisconnect(Client* client) {
	//TODO Marek
	//Vymaz z kontajneru, delete object

	auto it = std::find(m_clients.begin(), m_clients.end(), client);
	m_clients.erase(it);
	delete client;
}

bool ServerManager::clientLogIn(Client* client, std::string userName, std::string password) {
	//TODO Marek
	//Zavolaj userAuthentication a pripadne logInUser na Client

	if (userAuthentication(userName, password))
	{
		client->logInUser(userName);
		return true;
	}

	return false;
}

void ServerManager::clientLogOut(Client* client) {
	//TODO Marek
	//logOutUser na Client

	client->logOutUser();
}