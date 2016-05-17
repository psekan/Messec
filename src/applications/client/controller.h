//
// Created by Peter on 18.04.2016.
//

#ifndef MESSEC_CONTROLLER_H
#define MESSEC_CONTROLLER_H

#include <qglobal.h>
#include <QThread>
#include <clientManager.h>
#define  COMMAND_COUNT 12

using namespace std;

class Controler : public QThread
{
	Q_OBJECT
	enum commandsEnum { QUIT, CONNECT, DISCONNECT, SIGNIN, LOGIN, LOGOUT, USERS, CHAT, CHATEND, SEND, FILE, HELP };
	string commands[COMMAND_COUNT] = { "quit", "connect", "disconnect","signin", "login", "logout", "users", "chat", "chatend", "send", "file", "help" };
	ClientManager* clientMngr;

public:
	/**
	* constructor
	*/
	Controler(QObject *parent = 0, ClientManager* manager = 0);

	/**
	* destructor
	*/
	virtual ~Controler();

	
	/**
	* gets commands from cin and executes proper functions
	*/
	void run() override; 

signals:
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

	void startCommunicationWith(QString userName);

	void sendToMessenger(QString msg);

	void chatEnd();

	void sendFile(QString msg);
};


#endif //MESSEC_CONTROLLER_H
