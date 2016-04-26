//
// Created by Peter on 12.03.2016.
//

#ifndef MESSEC_CLIENTMANAGER_H
#define MESSEC_CLIENTMANAGER_H

#include <QStringList>
#include <QTcpSocket>
#include <string>
#include <vector>
#include <functional>
#include <mbedtls/rsa.h>
#include "messenger.h"
#include "../common/connectionErrors.h"
#include <QThread>
#include <QTcpServer>


class ClientManager : public QTcpServer {
	Q_OBJECT

	//Boolean values
    bool m_isConnected;
    bool m_isLoggedIn;

    //Connection with server
	QTcpSocket* m_serverSocket;
    mbedtls_rsa_context m_serverKey;
    unsigned char m_aesKey[32];

    //Connections with other clients
    std::vector<Messenger*> m_messengers;

    //Online users
    std::vector<std::string> m_onlineUsers;

public:
	/**
	* construcor
	*/
	ClientManager(QObject *parent);

	/**
	* destructor calls disconnect
	*/
	~ClientManager();

    /**
     * Check if client is connected to server.
     * @return bool true if connection is available
     */
    bool isConnected() const;

    /**
     * Check if client is logged in to the server.
     * @return bool true if user is logged in
     */
    bool isLoggedIn() const;

    /**
     * Get all active messengers
     * @return std::vector<Messenger*> container of references to messengers
     */
    std::vector<Messenger*> getMessengers() const;

    /**
     * Create new request for communication with other online user.
     * @param std::string user name
     * @return bool false if user is not logged in
     */
    bool startCommunicationWith(std::string userName);

	/**
	* Connect client to server.
	* @param std::string IPv4 of server
	* @param int tcp port number of server
	* @return bool true if connection is successfully realized.
	*/
	bool signalconnect(QString ip, int port);

	/**
	* Disconnect client from server.
	*/
	void disconnect();

	/**
	* Log out user.
	* Thread will be stopped, no more callbacks will be executed.
	*/
	void logOut();

	/**
	* Get names of all online users.
	* @return std::vector<std::string> container of users names
	*/
	void getOnlineUsers();


	/**
	* Sign in new user.
	* @param std::string user name
	* @param std::string password of user
	* @return bool true if new user is successfully signed in
	*/
	bool signIn(QString userName, QString password);

	/**
	* Log in to the server with user name and password.
	* If log in is successful, new thread is created and callbacks can be immediately executed.
	* @param std::string user name
	* @param std::string password of user
	* @return bool true if user is successfully logged in
	*/
	bool logIn(QString userName, QString password);

};


#endif //MESSEC_CLIENTMANAGER_H
