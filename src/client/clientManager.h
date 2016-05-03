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
	bool m_isChatting;

	//Connection with server
	QTcpSocket* m_serverSocket;
	QTcpSocket* m_peerSocket; ///////////////////////////////socket with other user

	mbedtls_rsa_context m_serverKey;
	unsigned char m_aesKey[32];
	uint32_t m_inCounter;
	uint32_t m_outCounter;

	//Connections with other clients
	quint16 m_clientPort;
	std::vector<Messenger*> m_messengers;

	//Online users
	std::vector<std::string> m_onlineUsers;

public:
	bool handleKeyDistribution();
	/**
		* construcor
		*/
	ClientManager(QObject *parent = 0);

	/**
	* destructor calls disconnect
	*/
	~ClientManager();

	/**
	* create Tcp server and listen
	* other clients connect to this server
	*/
	void start();

	/**
	* clientPort setter, port of server which listens for other clients
	*/
	void setPort(quint16 port) {
		m_clientPort = port;
	}

	/**
	* clientPort getter, port of server which listens for other clients
	*/
	quint16 getPort() {
		return m_clientPort;
	}

	/**
	* Check if client is chatting with other client
	* @return bool true if client is chatting
	*/
	bool isChatting() const {
		return m_isChatting;
	}

	/**
	 * Check if client is connected to server.
	 * @return bool true if connection is available
	 */
	bool isConnected() const {
		return m_isConnected;
	}

	/**
	 * Check if client is logged in to the server.
	 * @return bool true if user is logged in
	 */
	bool isLoggedIn() const {
		return m_isLoggedIn;
	}

	/**
	 * Get all active messengers
	 * @return std::vector<Messenger*> container of references to messengers
	 */
	std::vector<Messenger*> getMessengers() const;

protected:

	void incomingConnection(qintptr handle) override;
	
public slots:
	void deleteMessenger();

	/**
	* Connect client to server.
	* @param std::string IPv4 of server
	* @param int tcp port number of server
	*/
	void serverConnect(QString ip, quint16 port);

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
	*/
	void getOnlineUsers();
	/**
	* Sign in new user.
	* @param std::string user name
	* @param std::string password of user
	*/
	void signIn(QString userName, QString password);

	/**
	* Log in to the server with user name and password.
	* If log in is successful, new thread is created and callbacks can be immediately executed.
	* @param std::string user name
	* @param std::string password of user
	*/
	void logIn(QString userName, QString password);

	/**
	* Create new request for communication with other online user.
	* @param std::string user name
	*/
	void startCommunicationWith(QString userName);

	void sendToMessenger(QString msg);

	void chatEnd();

signals:
	void sendMsgSignal(QString msg);
	void disconnectClientSignal();

};
#endif //MESSEC_CLIENTMANAGER_H
