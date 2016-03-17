//
// Created by Peter on 13.03.2016.
//

#ifndef MESSEC_CLIENT_H
#define MESSEC_CLIENT_H

#include <string>
#include "../common/ipv4.h"

class ServerManager;

class Client {
    //Boolean values
    bool m_isLoggedIn;

    //Connection with client
    unsigned int m_socket;
    std::string m_userName;
    unsigned char m_aesKey[32]; //TODO

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
    Client(unsigned int socket);

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
     * Get client ip.
     * @return IPv4 ip
     */
    IPv4 getIPv4() const;

    /**
     * Encrypt message with aes key and send to client.
     * @param unsigned long long length of message in bytes
     * @param unsigned char* pointer to message data
     */
    bool sendMessage(unsigned long long messageLength, const unsigned char* message);
};


#endif //MESSEC_CLIENT_H
