//
// Created by Peter on 13.03.2016.
//
#include "serverManager.h"
#include <iostream>
#include <algorithm>
#include "messageTypes.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy_poll.h"
#include <iomanip>
#include <sstream>
#include <cstring>

#define NUMBER_OF_ITERATIONS 1000
#define SALT_LENGTH 32
#define PBKDF2_LENGTH 64

const int char_conversion = (sizeof(unsigned char) * 2);

int generateRandomNumber(unsigned char* output, int output_len)
{
	int result = 0;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *personalization = "nahodne_slova_na_zvysenie_entropie_toto_nie_je_seed";

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_add_source(&entropy, mbedtls_platform_entropy_poll, nullptr, 64, MBEDTLS_ENTROPY_SOURCE_STRONG);
	mbedtls_entropy_add_source(&entropy, mbedtls_hardclock_poll, nullptr, 16, MBEDTLS_ENTROPY_SOURCE_WEAK);

	result += mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		reinterpret_cast<const unsigned char *>(personalization), strlen(personalization));

	result += mbedtls_ctr_drbg_random(&ctr_drbg, output, output_len);

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return result;
}

int pbkdf2(unsigned char const* password, int password_len, unsigned char* salt, int salt_len, int number_of_it,
	unsigned char* pbkdf2_output, int output_len)
{
	int result = 0;
	mbedtls_md_context_t md_ctx;
	const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

	mbedtls_md_init(&md_ctx);
	result += mbedtls_md_setup(&md_ctx, md_info, 1);
	result += mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, password, password_len, salt, salt_len, number_of_it, output_len, pbkdf2_output);
	mbedtls_md_free(&md_ctx);

	return result;
}

void uCharToString(unsigned char* input, size_t input_len, std::string &output)
{
	std::ostringstream conversion_stream;

	for (size_t i = 0; i < input_len; ++i)
	{
		conversion_stream << std::hex << std::setw(char_conversion) << std::setfill('0') << static_cast<int>(input[i]);
	}

	output = conversion_stream.str();
}

void stringToUCHar(std::string &input, unsigned char* output)
{
	std::string byte;
	size_t j = 0;
	for (size_t i = 0; i < input.length(); i += char_conversion, ++j) {
		byte = input.substr(i, char_conversion);
		output[j] = (unsigned char)strtol(byte.c_str(), nullptr, char_conversion * 8);
	}
}

/*Constructor*/
ServerManager::ServerManager(std::string dbFilePath, qint16 port, quint16 keySize, QObject *parent) : QTcpServer(parent), port(port), m_database(dbFilePath) {
	//TODO init rsa
}

/*Network*/
void ServerManager::start()
{
	qDebug() << "Server start on " << port;
	if (!this->listen(QHostAddress::Any, port)) {
		qDebug() << "Server start failed";
		qDebug() << this->errorString();
		emit finished();
		exit(0);
	}
}

void ServerManager::incomingConnection(qintptr handle)
{
	Client* client = clientConnect(handle);
	connect(client, SIGNAL(disconnect()), this, SLOT(clientDisconnect()));
	connect(client, SIGNAL(finished()), this, SLOT(clientDisconnect()));
}

/*Database + client*/
void ServerManager::clearDatabase() {
	m_database.clearDatabase();
}

void ServerManager::removeUserFromDb(std::string userName) {
	if (!m_database.removeUser(userName))
	{
		std::cerr << "Client remove from database failed\n";
	}
}

bool ServerManager::userRegistration(std::string userName, std::string password) {
	if (password.length() < 8)
	{
		std::cerr << "Password was too short (length at least 8 characters is required)\n";
		return false;
	}

	UserDatabaseRow row = m_database.getUser(userName);

	if (row.getName().length() != 0)
	{
		std::cerr << "Username is taken\n";
		return false;
	}

	unsigned char salt[SALT_LENGTH];
	std::string salt_string;
	unsigned char pbkdf2_output[PBKDF2_LENGTH];
	std::string password_string;
	int result = 0;

	result += generateRandomNumber(salt, SALT_LENGTH);

	uCharToString(salt, SALT_LENGTH, salt_string);

	result += pbkdf2(reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), salt, SALT_LENGTH,
		NUMBER_OF_ITERATIONS, pbkdf2_output, PBKDF2_LENGTH);

	uCharToString(pbkdf2_output, PBKDF2_LENGTH, password_string);

	if (result == 0)
	{
		return m_database.insertUser(UserDatabaseRow(userName, password_string, salt_string));
	}

	std::cerr << "Some crypto fuction failed\n";
	return false;
}

bool ServerManager::userAuthentication(std::string userName, std::string password) {
	UserDatabaseRow row = m_database.getUser(userName);

	if (row.getName().compare("") == 0)
	{
		std::cerr << "Wrong username or password\n";
		return false;
	}

	std::string salt = row.getSalt();
	std::string row_hash = row.getPassword();
	unsigned char salt_char[SALT_LENGTH];
	unsigned char row_hash_char[PBKDF2_LENGTH];
	unsigned char pbkdf2_output[PBKDF2_LENGTH];
	int result = 0;

	stringToUCHar(salt, salt_char);
	stringToUCHar(row_hash, row_hash_char);

	result += pbkdf2(reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), salt_char, SALT_LENGTH,
		NUMBER_OF_ITERATIONS, pbkdf2_output, PBKDF2_LENGTH);

	if (result == 0) {
		if (memcmp(pbkdf2_output, row_hash_char, PBKDF2_LENGTH) == 0)
		{
			return true;
		}
		std::cerr << "Wrong username or password\n";
		return false;
	}
	std::cerr << "Some crypto fuction failed\n";
	return false;
}

/*Client operations*/
void ServerManager::kickUser(std::string userName) {
	std::string message = "You were kicked by server\n";

	QMutexLocker locker(&mutex);
	for (auto it = m_clients.begin(); it != m_clients.end(); ++it)
	{
		if (userName.compare((*it)->m_userName) == 0)
		{
			Client *client = *it;
			client->disconnect();
			return;
		}
	}
}

Client* ServerManager::clientConnect(qintptr socket) {
	Client* newClient = new Client(socket, this);
	newClient->start();
	QMutexLocker locker(&mutex);
	m_clients.push_back(newClient);
	return newClient;
}

void ServerManager::clientDisconnect() {
	Client* client = dynamic_cast<Client*>(sender());
	if (client == nullptr)
	{
		std::cerr << "Client is null\n";
		return;
	}

	QMutexLocker locker(&mutex);
	auto it = std::find(m_clients.begin(), m_clients.end(), client);
	m_clients.erase(it);
	delete client;
}

void ServerManager::clientLogIn(QString userName, QString password, Client* client) {
	
	std::cout << userName.toStdString() << " is trying to login with password: " << password.toStdString() << std::endl; //////////debug print
	
	if (client == nullptr)
	{
		std::cerr << "Client is null\n";
		return;
	}
	if (userAuthentication(userName.toStdString(), password.toStdString()))
	{
		client->sendMessage(MESSAGETYPE_LOGIN_SUCCESS, "OK");
		client->logInUser(userName.toStdString());
		std::cout << "login OK" << std::endl;
	}
	else
	{
		client->sendMessage(MESSAGETYPE_LOGIN_FAIL, "NOK");
		std::cout << "login FAIL" << std::endl;
	}
}

void ServerManager::clientSignIn(QString userName, QString password, Client* client) {
	
	std::cout << userName.toStdString() << " is trying to signin with password: " << password.toStdString() << std::endl;

	if (client == nullptr)
	{
		std::cerr << "Client is null\n";
		return;
	}

	if (userRegistration(userName.toStdString(), password.toStdString()))
	{
		client->sendMessage(MESSAGETYPE_SIGNIN_SUCCESS, "OK");
		client->logInUser(userName.toStdString());
		std::cout << "signin OK" << std::endl;
	}
	else
	{
		client->sendMessage(MESSAGETYPE_SIGNIN_FAIL, "NOK");
		std::cout << "signin FAIL" << std::endl;
	}
}

void ServerManager::clientLogOut(Client* client) {
	if (client == nullptr)
	{
		std::cerr << "Client is null\n";
		return;
	}
	client->logOutUser();
}

void ServerManager::getOnlineUsers(Client* client) {

	/*	if (!client->isLoggedIn())              // toto je zakomentovane pre ucely testovania, testuje sa to ak v klientova pre istotu
	{
		client->sendMessage(MESSAGETYPE_LOGIN_SUCCESS, QString(""));  //  zatial je tam nahodna sprava tak aby to nieco poslalo a nebolo toto spravne
		return;
	}*/

	if (client == nullptr)
	{
		std::cerr << "Client is null\n";
		return;
	}

	QString message;
	QMutexLocker locker(&mutex);          
	for (auto it = m_clients.begin(); it != m_clients.end(); ++it)
	{
		if ((*it)->isLoggedIn())
		{
			if (it != m_clients.begin()) {
				message += "|#|";
			}
			message += QString::fromStdString((*it)->m_userName);
		}
	}
	locker.unlock();
	if (message.toStdString() == "")
		message += "--------";
	std::cout << "list to send: " << message.toStdString() << std::endl;
	client->sendMessage(MESSAGETYPE_GET_ONLINE_USERS, message);
}

/*TODO*/
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

