//
// Created by Peter on 13.03.2016.
//

#ifndef MESSEC_SERVERMANAGER_H
#define MESSEC_SERVERMANAGER_H

#include <string>
#include <vector>
#include <mbedtls/rsa.h>
#include "client.h"
#include "database.h"
#include <set>
#include <QtCore/qglobal.h>

#if defined(SERVER_LIBRARY)
#  define SERVERSHARED_EXPORT Q_DECL_EXPORT
#else
#  define SERVERSHARED_EXPORT Q_DECL_IMPORT
#endif

class SERVERSHARED_EXPORT ServerManager {
    unsigned int m_socket;
    mbedtls_rsa_context m_rsaKey;
    std::vector<Client*> m_clients;
    bool m_isRunning;
	Database m_database;

    /**
     * Process client incoming requests.
     * @param Client
     */
    void processClientCommunication(Client* client);

    /**
     * Process new requests for connection.
     * Create Client objects and save them to container.
     */
    void processNewConnectionRequests();

    /**
     * Send new request from one client to other with hash to later verification.
     * @param Client& client who created request
     * @param Client& requested client
     * @param unsigned char[16] verification hash
     */
    void sendNewRequestToClient(Client* from, Client* to, unsigned char hash[16]);

    /**
     * Generate aes key and send them to both client and send to clients their ip addresses.
     * @param Client&
     * @param Client&
     */
    void createCommunicationBetween(Client* communicationServer, Client* communicationClient);
public:
    /**
     * Create new server manager on sqlite database.
     * @exception DatabaseAccessForbidden if cannot read or create database file
     * @param std::string path to sqlite database
     */
    ServerManager(std::string dbFilePath);

    /**
     * Start server on port and public RSA key with specific length.
     * @param int port on tcp protocol
     * @param unsigned int length of rsa key in bits
     * @return bool false if port is not available
     */
    bool start(int port, unsigned int keySize);

    /**
     * Stop server.
     */
    void stop();

    /**
     * Clear whole database, all users.
     * Cannot be execute if server is running.
     */
    void clearDatabase();

    /**
     * Return all names of online users.
     * @return std::vector<std::string> container of users names
     */
    std::vector<std::string> getOnlineUsers();
	/**
	 * Remove specific user from database
	 * @param std::string user name
	 */
    void removeUserFromDb(std::string userName);

    /**
     * Close connection with user.
     * @param std::string name of user.
     */
    void kickUser(std::string userName);

    /**
     * Check if server is running.
     * @return bool
     */
    bool isRunning() const;

	/**
	 * Add new user to database.
	 * @param std::string user name
	 * @param std::string password
	 * @return bool false if registration fails (user already exists, bad format of password, ...)
	 */
	bool userRegistration(std::string userName, std::string password);

	/**
	 * Authentication of user
	 * @param std::string user name
	 * @param std::string password
	 * @return bool false if authentication fails (user not exists, bad password, ...)
	 */
	bool userAuthentication(std::string userName, std::string password);

	/**
	 * New client is connected
	 * @param unsigned int socket
	 * @return Client& new client 
	 */
	Client* clientConnect(unsigned int socket);

	/**
	 * Disconnect client
	 * @param Client* client, after call this function, pointer will be invalid
	 */
	void clientDisconnect(Client* client);
	/**
	 * Log in client as user
	 * @param Client& client object
	 * @param std::string user name
	 * @param std::string user password
	 * @return bool false if cannot log in user
	 */
	bool clientLogIn(Client* client, std::string userName, std::string password);

	/**
	 * Log out client as some user
	 */
	void clientLogOut(Client* client);
};

#endif //MESSEC_SERVERMANAGER_H
