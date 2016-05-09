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
   
public:
	/**
	* @brief Create new server manager on sqlite database.
	* @exception DatabaseAccessForbidden if cannot read or create database file
	* @param std::string path to sqlite database
	* @param qint16 port on tcp protocol
	* @param quint16 length of rsa key in bits
	*/
	explicit ServerManager(std::string dbFilePath, quint16 port, quint16 keySize, QObject *parent = 0);

	~ServerManager();

	/**
	* @brief Generate aes key and send them to both client and send to clients their ip addresses.
	* @param Client* srcClient initializator of communication
	* @param QString userName of partner to connect
	*/
	void createCommunication(Client* srcClient, QString userName);

	/**
	* @brief RSA key getter
	*/
	mbedtls_pk_context getRSAKey() const;

	/**
	* @brief start Method starts infinite loop
	*/
	void start();   

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
	 * @param qintptr socket
	 * @return Client* new client 
	 */
	Client* clientConnect(qintptr socket);

	/**
	* check if user is online
	* @param QString name of user to check
	* @return bool true if client is logged in
	*/
	bool isOnline(QString name);

	/**
	* Clear whole database, all users.
	* Cannot be execute if server is running.
	* NOT USED
	*/
	void clearDatabase();

	/**
	* Remove specific user from database
	* @param std::string user name
	* NOT USED
	*/
	void removeUserFromDb(std::string userName);

	/**
	* Close connection with user.
	* @param std::string name of user.
	* NOT USED
	*/
	void kickUser(std::string userName);

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
	 * @param QString user name
	 * @param QString user password
	 */
	void clientLogIn(QString userName, QString password, Client* client);

	/**
	* Sign in client as user
	* @param std::string user name
	* @param std::string user password
	* @param Client* client object
	*/
	void clientSignIn(QString userName, QString password, Client* client);

	/**
	 * Log out client as some user
	 */
	void clientLogOut(Client* client);

	/**
	* Sends list of all online users to client
	* @param Client* client who wants the list
	*/
	void getOnlineUsers(Client* client);

	/**
	* @brief RSA key generator
	*/
	int generateRSAKey();
};

#endif //MESSEC_SERVERMANAGER_H
