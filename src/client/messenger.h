//
// Created by Peter on 12.03.2016.
//

#ifndef MESSEC_MESSENGER_H
#define MESSEC_MESSENGER_H


#include <string>
#include <functional>
#include "../common/connectionErrors.h"
#include <QObject>
#include <QThread>
#include <QTcpSocket>

class ClientManager;

class Messenger : public QThread {

	Q_OBJECT

    //bool true if messengers are authenticated and communicating
    bool m_isAlive;

    //Connection with other client
    std::string m_userName;
    unsigned char m_aesKey[32];
	unsigned char m_aesIv[32];
	uint32_t m_inCounter;
	uint32_t m_outCounter;
	qintptr sock_ptr;
	QTcpSocket *socket;
	unsigned char m_randomNumbers[64];
	unsigned char* m_clientMngrAes; // pointer to AES key between client and server

    //Buffer for reading
	size_t m_messageLength = 0;
	QByteArray m_readingBuffer;
	
	//Access for ClientManager
    friend class ClientManager;

	//Constants
	const static size_t TAG_SIZE = 16;

	void saveFile(QString name, QByteArray content);
	bool serverHandshakeAuthentication(uint32_t initLength, const unsigned char* decryptedInit);
public:
	//Constant
	const static size_t MESSAGE_INFO_SIZE = 37;

	/**
	*
	*/
	void run() override;

	/**
	* Constructor used for sending request for intitialization of communication (client)
	* @param QString ip address of host server
	* @param quint16 port of host server
	* @param unsigned char* dataToSendB data required for authentication protocol
	* @param quint32 dataLenght length of dataToSendB
	* @param unsigned char* randomNumbers random number required for authentication protocol
	* @param QObject *parent parent for Qobject hierarchy
	*/
	Messenger(QString ip, quint16 port, unsigned char* dataToSendB, quint32 dataLenght, unsigned char* randomNumbers, QObject *parent);

	/**
	* Constructor used in incomming communication (server)
	* @param qintptr SocketDescriptor descriptor of socket which wants to connect
	* @param QObject *parent parent for Qobject hierarchy
	* @param unsigned char* clientMngrAes aes key of manager communicating with server
	*/
	Messenger(qintptr SocketDescriptor, QObject *parent, unsigned char* clientMngrAes);

	/**
	* Destructor disconnects and delete socket
	*/
	~Messenger();

    /**
     * Check if connection between clients is alive.
     * @return bool true if connection is alive.
     */
    bool isAlive() const;

	/**
	* setting the same key with other client through diffie-hellman, client part
	* partners run authentication protocol
	*/
	bool Messenger::clientHandshake();

	/**
	* setting the same key with other client through diffie-hellman, server part
	* partners run authentication protocol
	*/
	bool Messenger::serverHandshake();
	bool clientHandshakeAuthentication();

public slots:
	void readData();
	void sendEncrypted(QString msg);
	void quitMessenger(); 
	void sendFile(QString msg);

};


#endif //MESSEC_MESSENGER_H
