//
// Created by Peter on 12.03.2016.
//

#ifndef MESSEC_MESSENGER_H
#define MESSEC_MESSENGER_H


#include <string>
#include <functional>
#include "../common/connectionErrors.h"

class ClientManager;

class Messenger {
    //Callbacks
    std::function<void(Messenger&, ConnectionErrors)> m_connectionLostCallback;
    std::function<void(Messenger&)> m_communicationEndedCallback;
    std::function<void(Messenger&,unsigned char,unsigned long long,unsigned char*)> m_newMessageCallback;

    //Boolean values
    bool m_isAlive;

    //Connection with other client
    std::string m_userName;
    unsigned int m_socket;
    unsigned char m_aesKey[32];
	unsigned char m_aesIv[32];
	unsigned int m_counter;

    //Access for ClientManager
    friend class ClientManager;

    /**
     * Set key for secured communication.
     * @param unsigned char[32] aes key for secured communication
     * @param unsigned char[32] aes initialization vector for secured communication
     */
    void setAes(unsigned char aesKey[32], unsigned char aesIv[32]);
public:
	/**
	* Constructor for ClientManager.
	* @param std::string user name of other client
	*/
	Messenger(std::string userName, unsigned int socket, unsigned char aesKey[32], unsigned char aesIv[32], unsigned int counter);

    /**
     * Set messenger's callbacks. First argument in all callbacks is reference to messenger, which execute callback.
     * @param connectionLostCallback           Connection with other client was lost. Messenger will be no longer alive.
     * @param communicationEndedCallback       Other user call exitCommunication function. Messenger will be no longer alive.
     * @param newMessageCallback               New message was received from other user.
     */
    void setCallbacks(std::function<void(Messenger&, ConnectionErrors)> connectionLostCallback,
                      std::function<void(Messenger&)> communicationEndedCallback,
                      std::function<void(Messenger&,unsigned char,unsigned long long,unsigned char*)> newMessageCallback);

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
     * @param unsigned long long length of message in bytes
     * @param unsigned char* message's bytes
     * @return bool true is message was successfully sent
     */
    bool sendMessage(unsigned char messageType, unsigned long long messageLength, unsigned char* message);
	
	static bool encrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key);

	static bool decrypt(const unsigned char * input, size_t inlen, unsigned char * output, const unsigned char* iv, size_t iv_len, unsigned char* tag, const unsigned char* key);

};


#endif //MESSEC_MESSENGER_H
