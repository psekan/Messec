//
// Created by Peter on 13.03.2016.
//

#ifndef MESSEC_CLIENT_H
#define MESSEC_CLIENT_H

#include <qglobal.h>
#include <QObject>
#include <QThread>
#include <QTcpSocket>

#include <string>
#include "../common/ipv4.h"

class ServerManager;

class Client : public QThread
{
	Q_OBJECT
	qintptr sock_ptr;
	QTcpSocket *socket;
	quint16 clientPort;

    //Boolean values
    bool m_isLoggedIn;
	bool readyToCommuinicate;

    //Connection with client
    std::string m_userName;
    unsigned char m_aesKey[32]; //TODO
	uint32_t m_inCounter;
	uint32_t m_outCounter;

	/**
	 * Set client as logged in with user name
	 * @param std::string user name
	 */
	void logInUser(std::string userName);

	/**
	* Set client as logged out
	*/
	void logOutUser();

    //Access for ServerManager
    friend class ServerManager;
public:
    /**
     * Create client structure on socket.
     * @param unsigned int socket
     */
	explicit Client(qintptr socket, QObject *parent = 0);

	void sendRSA();
	void setAES();
	void run() override;

    /**
     * Destroy client structure and close connection.
     */
    ~Client();

    /**
     * Check if user is logged in.
     * @return bool
     */
    bool isLoggedIn() const;

	/**
	* clientPort setter, port of server which listens for other clients
	*/
	void setClientPort(quint16 port) {
		clientPort = port;
	}

	/**
	* clientPort getter, port of server which listens for other clients
	*/
	quint16 getClientPort() {
		return clientPort;
	}

    /**
     * Get client ip.
     * @return IPv4 ip
     */
    IPv4 getIPv4() const;

    /**
     * Encrypt message with aes key and send to client.
     * @param unsigned long long length of message in bytes
     * @param unsigned char* pointer to message data
     */
    bool sendMessage(quint8 messageType, QString message);

signals:
	
	/**
	* Log in client as user
	* @param Client& client object
	* @param std::string user name
	* @param std::string user password
	* @return bool false if cannot log in user
	*/
	void logIn(QString userName, QString password);

	/**
	* Log in client as user
	* @param Client& client object
	* @param std::string user name
	* @param std::string user password
	* @return bool false if cannot log in user
	*/
	void signIn(QString userName, QString password);

	/**
	  Log out client as some user
	 */
	void logOut();

	void getOnlineUsers();

private slots :

	/**
	 * @brief readData slot which is runned on readyRead signal from socket
	 * This slot reads data from socket and then sends back response
	 */
	void readData();

	/**
	 * @brief quit slot which is runned on disconnected signal from socket
	 * This slot ends the thread and emits signal finished (this behaviour is inherited from QThread)
	 */
	void quit();
};


#endif //MESSEC_CLIENT_H
