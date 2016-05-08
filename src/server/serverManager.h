//
// Created by Peter on 13.03.2016.
//

#ifndef MESSEC_SERVERMANAGER_H
#define MESSEC_SERVERMANAGER_H

#include <qglobal.h>
#include <QObject>
#include <QTcpServer>
#include <QDataStream>
#include <string>
#include <vector>
#include <mbedtls/rsa.h>
#include "client.h"
#include "database.h"
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

class ServerManager : public QTcpServer
{
	Q_OBJECT
	quint16 port;
	
    mbedtls_pk_context m_rsaKey;
    std::vector<Client*> m_clients;
	Database m_database;
	mutable QMutex mutex;

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

   
public:
	/**
	* Create new server manager on sqlite database.
	* @exception DatabaseAccessForbidden if cannot read or create database file
	* @param std::string path to sqlite database
	* @param qint16 port on tcp protocol
	* @param quint16 length of rsa key in bits
	*/
	explicit ServerManager(std::string dbFilePath, quint16 port, quint16 keySize, QObject *parent = 0);

	~ServerManager();

	/**
	* Generate aes key and send them to both client and send to clients their ip addresses.
	* @param Client&
	* @param Client&
	*/
	void createCommunication(Client* srcClient, QString userName);
	mbedtls_pk_context getRSAKey() const;

	/**
	* @brief start Method starts infinite loop
	*/
	void start();   

    /**
     * Clear whole database, all users.
     * Cannot be execute if server is running.
     */
    void clearDatabase();

	/**
	 * Remove specific user from database
	 * @param std::string user name
	 */
    void removeUserFromDb(std::string userName);

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
     * Close connection with user.
     * @param std::string name of user.
     */
    void kickUser(std::string userName);	

	/**
	 * New client is connected
	 * @param qintptr socket
	 * @return Client* new client 
	 */
	Client* clientConnect(qintptr socket);

	/**
	* check if user is online
	* @param QString name of user to check
	* @return true if client is logged in
	*/
	bool isOnline(QString name);

protected:
	/**
	 * @brief incomingConnection Method is evoked when new connection is established
	 * Method starts new thread which handles communication with client
	 * @param handle socket descriptor assigned to new connection
	 */
	void incomingConnection(qintptr handle) override;

signals:
	/**
	 * @brief finished Signal emited when the server was closed by error
	 */
	void finished();

public slots:
	/**
	 * Disconnect client
	 */
	void clientDisconnect();
	
	/**
	 * Log in client as user
	 * @param Client& client object
	 * @param std::string user name
	 * @param std::string user password
	 * @return bool false if cannot log in user
	 */
	void clientLogIn(QString userName, QString password, Client* client);

	/**
	* Sign in client as user
	* @param Client& client object
	* @param std::string user name
	* @param std::string user password
	* @return bool false if cannot log in user
	*/
	void clientSignIn(QString userName, QString password, Client* client);

	/**
	 * Log out client as some user
	 */
	void clientLogOut(Client* client);

	void getOnlineUsers(Client* client);

	int generateRSAKey();
};

#endif //MESSEC_SERVERMANAGER_H
