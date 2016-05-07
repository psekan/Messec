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

    //Boolean values
    bool m_isAlive;

    //Connection with other client
    std::string m_userName;
    unsigned int m_socket;
    unsigned char m_aesKey[32];
	unsigned char m_aesIv[32];
	uint32_t m_inCounter;
	uint32_t m_outCounter;
	qintptr sock_ptr;
	QTcpSocket *socket;
	unsigned char m_randomNumbers[64];
	
    //Access for ClientManager
    friend class ClientManager;

	//Constants
	const static size_t TAG_SIZE = 16;

    /**
     * Set key for secured communication.
     * @param unsigned char[32] aes key for secured communication
     * @param unsigned char[32] aes initialization vector for secured communication
     */
    void setAes(unsigned char aesKey[32], unsigned char aesIv[32]);

	/**
	* Add data to buffer
	* @param unsigned char*& buffer
	* @param const unsigned char* data
	* @param const unsigned char* length of data
	*/
	static void addToBuffer(unsigned char*&buffer, const unsigned char* data, size_t dataLength);

	void saveFile(QString name, QByteArray content);
public:
	//Constant
	const static size_t MESSAGE_INFO_SIZE = 37;

	Messenger(){}

	void run() override;

	Messenger(QString ip, quint16 port, QString name, unsigned char* dataToSendB, quint32 dataLenght, unsigned char* randomNumbers, QObject *parent);

	Messenger(qintptr SocketDescriptor, QObject *parent);

	/**
	* Constructor for ClientManager.
	* @param std::string user name of other client
	*/
	Messenger(std::string userName, unsigned int socket, unsigned char aesKey[32], unsigned char aesIv[32], unsigned int inCounter, unsigned int outCounter);

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
     * Send to the other client message communicationEnded and exit communication.
     * This messenger will be not usable after call this function.
     */
    void exitCommunication();


    /**
     * Send message to other client with some message type.
     * @param unsigned char message type - number in interval [0-255]
     * @param size_t length of message in bytes
     * @param unsigned char* message's bytes
     * @return bool true is message was successfully sent
     */
    bool sendMessageC(unsigned char messageType, size_t messageLength, const unsigned char* message);

	/**
	 * Build byte stream to send other client
     * @param unsigned char message type - number in interval [0-255]
     * @param size_t length of message in bytes
     * @param unsigned char* message's bytes
	 * @param unsigned char* prepared message - pointer to allocated memory of size (messageLength + MESSAGE_INFO_SIZE)
	 * @return bool true is message was successfully sent
	 */
	bool prepareMessageToSend(unsigned char messageType, size_t messageLength, const unsigned char* message, unsigned char* preparedMessage);

	/**
	 * Parse received message from other client.
	 * @param unsigned char* received message
	 * @param size_t length of received message in bytes
	 * @param unsigned char message type - number in interval [0-255]
	 * @param unsigned char* message's bytes - pointer to allocated memory of size (receivedMessageLength - MESSAGE_INFO_SIZE)
	 * @return bool true is message was successfully sent
	 */
	bool parseReceivedMessage(const unsigned char* receivedMessage, size_t receivedMessageLength, unsigned char& messageType, unsigned char* message);

	/**
	 * encryption of message
	 * @param const unsigned char* message to encrypt
	 * @param size_t length of message
	 * @param unsigned char* encrypted message
	 * @param const unsigned char* initialization vector
	 * @param size_t length of initialization vector
	 * @param unsigned char* buffer holding tag of encrypted message
	 * @param const unsigned char* key for encryption 
	 */
	static bool encrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key);

	/**
	 * decryption of message
	 * @param const unsigned char* message to decrypt
	 * @param size_t length of message
	 * @param unsigned char* decrypted message
	 * @param const unsigned char* initialization vector
	 * @param size_t length of initialization vector
	 * @param unsigned char* buffer holding tag to authenticate message
	 * @param const unsigned char* key for decryption
	 */
	static bool decrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, const unsigned char* tag, const unsigned char* key);

	/**
	* setting the same key with other client through diffie-hellman, client part
	* @param 
	*/
	bool Messenger::clientHandshake();

	/**
	* setting the same key with other client through diffie-hellman, server part
	* @param
	*/
	bool Messenger::serverHandshake();


public slots:
	void readData();
	void sendNotCrypted(QString msg);
	void quitMessenger(); 
	void sendFile(QString msg);

};


#endif //MESSEC_MESSENGER_H
