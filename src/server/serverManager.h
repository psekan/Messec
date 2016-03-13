//
// Created by Peter on 13.03.2016.
//

#ifndef MESSEC_SERVERMANAGER_H
#define MESSEC_SERVERMANAGER_H

#include <string>
#include <vector>
#include <mbedtls/rsa.h>
#include "client.h"

class ServerManager {
    unsigned int m_socket;
    mbedtls_rsa_context m_rsaKey;
    std::vector<Client> m_clients;
    bool m_isRunning;

    /**
     * Add new user to database.
     * @param std::string user name
     * @param std::string password
     * @return bool false if user with same name already exists
     */
    bool addUserToDatabase(std::string userName, std::string password);

    /**
     * Process client incoming requests.
     * @param Client
     */
    void processClientCommunication(Client& client);

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
    void sendNewRequestToClient(Client& from, Client& to, unsigned char hash[16]);

    /**
     * Generate aes key and send them to both client and send to clients their ip addresses.
     * @param Client&
     * @param Client&
     */
    void createCommunicationBetween(Client& communicationServer, Client& communicationClient);
public:
    /**
     * Create new server manager on sqlite database.
     * @exception exception if cannot read database file
     * @param std::string path to sqlite database
     */
    ServerManager(std::string dbFilePath);

    /**
     * Start server on port and public RSA key with specific length.
     * @param int port on tcp protocol
     * @param unsigned int length of rsa key in bits
     * @return bool false if port is not available
     */
    bool start(int port, unsigned int keySize);

    /**
     * Stop server.
     */
    void stop();

    /**
     * Clear whole database, all users.
     * Cannot be execute if server is running.
     */
    void clearDatabase();

    /**
     * Return all names of online users.
     * @return std::vector<std::string> container of users names
     */
    std::vector<std::string> getOnlineUsers();

    /**
     * Remove specific user from database
     * @param std::string user name
     */
    void removeUserFromDb(std::string userName);

    /**
     * Close connection with user.
     * @param std::string name of user.
     */
    void kickUser(std::string userName);

    /**
     * Check if server is running.
     * @return bool
     */
    bool isRunning() const;
};

#endif //MESSEC_SERVERMANAGER_H
