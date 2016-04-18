//
// Created by Peter on 12.03.2016.
//

#ifndef MESSEC_CLIENTMANAGER_H
#define MESSEC_CLIENTMANAGER_H

#include <qglobal.h>
#include <QTcpSocket>
#include <string>
#include <vector>
#include <functional>
#include <mbedtls/rsa.h>
#include "messenger.h"
#include "../common/connectionErrors.h"
#include <QThread>

class ClientManager : public QThread {
	Q_OBJECT

    //Callbacks
    /*std::function<void(ConnectionErrors)> m_connectionLostCallback;
    std::function<void(std::string,bool)> m_userChangeStatusCallback;
    std::function<bool(std::string)> m_newRequestCallback;
    std::function<void(std::string)> m_requestRejectedCallback;
    std::function<void(std::string, Messenger*)> m_newCommunicationStartedCallback;*/

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

	void run() override;
public:
    /**
     * Create new client manager and set callbacks. First argument in all callbacks is user name.
     * @param connectionLostCallback           Connection with server was lost. User will be log out and no more callbacks will be executed.
     * @param userChangeStatusCallback         User is logged in (second argument == true) or logged out (false).
     * @param newRequestCallback               User want to communicate with this client. Is callback return true, request is accepted, otherwise is rejected.
     * @param requestRejectedCallback          User reject this client request for communication.
     * @param newCommunicationStartedCallback  Request was accepted and communication started. Communication is handled with Messenger in second argument.
     */
    /*ClientManager(std::function<void(ConnectionErrors)> connectionLostCallback,
                  std::function<void(std::string,bool)> userChangeStatusCallback,
                  std::function<bool(std::string)> newRequestCallback,
                  std::function<void(std::string)> requestRejectedCallback,
                  std::function<void(std::string, Messenger*)> newCommunicationStartedCallback);*/
	ClientManager(QObject *parent = 0);

	~ClientManager();

    /**
     * Check if client is connected to server.
     * @return bool true if connection is available
     */
    bool isConnected() const;

    /**
     * Disconnect client from server.
     */
    void disconnect();

    /**
     * Sign in new user.
     * @param std::string user name
     * @param std::string password of user
     * @return bool true if new user is successfully signed in
     */
    bool signIn(std::string userName, std::string password);

    /**
     * Log in to the server with user name and password.
     * If log in is successful, new thread is created and callbacks can be immediately executed.
     * @param std::string user name
     * @param std::string password of user
     * @return bool true if user is successfully logged in
     */
    bool logIn(std::string userName, std::string password);

    /**
     * Check if client is logged in to the server.
     * @return bool true if user is logged in
     */
    bool isLoggedIn() const;

    /**
     * Log out user.
     * Thread will be stopped, no more callbacks will be executed.
     */
    void logOut();

    /**
     * Get names of all online users.
     * @return std::vector<std::string> container of users names
     */
    std::vector<std::string> getOnlineUsers() const;

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
signals:
	void connectionLost();

	void signalconnected(bool isConnected);

public slots:
	/**
	* Connect client to server.
	* @param std::string IPv4 of server
	* @param int tcp port number of server
	* @return bool true if connection is successfully realized.
	*/
	void signalconnect(QString ip, int port);
};


#endif //MESSEC_CLIENTMANAGER_H
