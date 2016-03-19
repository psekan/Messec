//
// Created by Peter on 13.03.2016.
//
#include "serverManager.h"
#include <iostream>
#include <algorithm>
#include "mbedtls/pkcs5.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy_poll.h"
#include <iomanip>
#include <sstream>

#define NUMBER_OF_ITERATIONS 1000
#define SALT_LENGTH 32
#define PBKDF2_LENGTH 64

int char_conversion = (sizeof(unsigned char) * 2);

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

ServerManager::ServerManager(std::string dbFilePath) : m_database(dbFilePath), m_isRunning(false) {

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
		std::cerr << "Client remove from database failed\n";
	}
}

void ServerManager::kickUser(std::string userName) {
	//TODO Marek
	//clientLogOut a clientDisconnect
	std::string message = "You were kicked by server\n";

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

	if (password.length() < 8)
	{
		std::cerr << "Password was too short (length at least 8 characters is required)";
		return false;
	}

	unsigned char salt[SALT_LENGTH];
	unsigned char pbkdf2_output[PBKDF2_LENGTH];
	const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
	mbedtls_md_context_t md_ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	char *personalization = "nahodne_slova_na_zvysenie_entropie_toto_nie_je_seed";
	std::ostringstream conversion_stream;
	int result = 0;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_add_source(&entropy, mbedtls_platform_entropy_poll, nullptr, 512, MBEDTLS_ENTROPY_SOURCE_STRONG);
	mbedtls_entropy_add_source(&entropy, mbedtls_hardclock_poll, nullptr, 64, MBEDTLS_ENTROPY_SOURCE_WEAK);
	result += mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
		reinterpret_cast<const unsigned char *>(personalization), strlen(personalization));
	result += mbedtls_ctr_drbg_random(&ctr_drbg, salt, SALT_LENGTH);

	for (size_t i = 0; i < SALT_LENGTH; ++i)
	{
		conversion_stream << std::hex << std::setw(char_conversion) << std::setfill('0') << static_cast<int>(salt[i]);
	}

	std::string salt_string = conversion_stream.str();
	
	conversion_stream.clear();
	conversion_stream.str("");

	mbedtls_md_init(&md_ctx);
	result += mbedtls_md_setup(&md_ctx, md_info, 1);
	result += mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, reinterpret_cast<const unsigned char*>(password.c_str()),
		password.length(), salt, SALT_LENGTH, NUMBER_OF_ITERATIONS, PBKDF2_LENGTH, pbkdf2_output);
		
	for (size_t i = 0; i < PBKDF2_LENGTH; ++i)
	{
		conversion_stream << std::hex << std::setw(char_conversion) << std::setfill('0') << static_cast<int>(pbkdf2_output[i]);
	}

	std::string password_string = conversion_stream.str();

	mbedtls_md_free(&md_ctx);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	if(result == 0)
	{
		return m_database.insertUser(UserDatabaseRow(userName, password_string, salt_string));
	}

	std::cerr << "Some crypto fuction failed\n";
	return false;
}

bool ServerManager::userAuthentication(std::string userName, std::string password) {
	//TODO Marek
	//Cisto overenie udajov na db

	UserDatabaseRow row = m_database.getUser(userName);
	std::string salt = row.getSalt();
	std::string row_hash = row.getPassword();
	unsigned char salt_char[SALT_LENGTH];
	unsigned char row_hash_char[PBKDF2_LENGTH];
	unsigned char pbkdf2_output[PBKDF2_LENGTH];
	const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
	mbedtls_md_context_t md_ctx;
	std::string byte;
	size_t j = 0;
	int result = 0;

	for (size_t i = 0; i < salt.length(); i += char_conversion, ++j) {
		byte = salt.substr(i, char_conversion);
		salt_char[j] = strtol(byte.c_str(), nullptr, char_conversion * 8);
	}
	
	for (size_t i = 0; i < row_hash.length(); i += char_conversion, ++j) {
		byte = row_hash.substr(i, char_conversion);
		row_hash_char[j] = strtol(byte.c_str(), nullptr, char_conversion * 8);
	}

	mbedtls_md_init(&md_ctx);
	mbedtls_md_setup(&md_ctx, md_info, 1);
	mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), 
		salt_char, SALT_LENGTH, NUMBER_OF_ITERATIONS, PBKDF2_LENGTH, pbkdf2_output);

	mbedtls_md_free(&md_ctx);

	if (memcpy(pbkdf2_output, row_hash_char, PBKDF2_LENGTH) == 0)
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
	if (client == nullptr)
	{
		std::cerr << "Client is null\n";
		return;
	}

	std::string message = "You will be disconected\n";

	client->sendMessage(message.length(), reinterpret_cast<const unsigned char*>(message.c_str()));
	auto it = std::find(m_clients.begin(), m_clients.end(), client);
	m_clients.erase(it);
	delete client;
}

bool ServerManager::clientLogIn(Client* client, std::string userName, std::string password) {
	//TODO Marek
	//Zavolaj userAuthentication a pripadne logInUser na Client
	if (client == nullptr)
	{
		std::cerr << "Client is null\n";
		return;
	}
	
	std::string message; 
	
	if (userAuthentication(userName, password))
	{
		message = "Login successful\n";
		client->sendMessage(message.length(), reinterpret_cast<const unsigned char*>(message.c_str()));
		client->logInUser(userName);
		return true;
	}
	message = "Invalid login data\n";
    client->sendMessage(message.length(), reinterpret_cast<const unsigned char*>(message.c_str()));
	return false;
}

void ServerManager::clientLogOut(Client* client) {
	//TODO Marek
	//logOutUser na Client
	if(client == nullptr)
	{
		std::cerr << "Client is null\n";
		return;
	}
	std::string message = "You were logged off\n";
	client->sendMessage(message.length(), reinterpret_cast<const unsigned char*>(message.c_str()));
	client->logOutUser();
}