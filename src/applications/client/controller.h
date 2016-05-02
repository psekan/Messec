//
// Created by Peter on 18.04.2016.
//

#ifndef MESSEC_CONTROLLER_H
#define MESSEC_CONTROLLER_H

#include <qglobal.h>
#include <iostream>
#include <QThread>
#include <clientManager.h>
#include <string>
#define  COMMAND_COUNT 11

using namespace std;

class Controler : public QThread
{
	Q_OBJECT
	enum commandsEnum { QUIT, CONNECT, DISCONNECT, SIGNIN, LOGIN, LOGOUT, USERS, CHAT, CHATEND, SEND, HELP };
	string commands[COMMAND_COUNT] = { "quit", "connect", "disconnect","signin", "login", "logout", "users", "chat", "chatend", "send", "help" };
	ClientManager* clientMngr;

public:
	/**
	* constructor
	*/
	Controler(QObject *parent = 0, ClientManager* manager = 0) : QThread(parent), clientMngr(manager)
	{
		QObject::connect(this, SIGNAL(serverConnect(QString, quint16)), manager, SLOT(serverConnect(QString, quint16)));
		QObject::connect(this, SIGNAL(disconnect()), manager, SLOT(disconnect()));
		QObject::connect(this, SIGNAL(logOut()), manager, SLOT(logOut()));
		QObject::connect(this, SIGNAL(getOnlineUsers()), manager, SLOT(getOnlineUsers()));
		QObject::connect(this, SIGNAL(signIn(QString, QString)), manager, SLOT(signIn(QString, QString)));
		QObject::connect(this, SIGNAL(logIn(QString, QString)), manager, SLOT(logIn(QString, QString)));
		QObject::connect(this, SIGNAL(startCommunicationWith(QString)), manager, SLOT(startCommunicationWith(QString)));
		QObject::connect(this, SIGNAL(sendToMessenger(QString)), manager, SLOT(sendToMessenger(QString)));
		QObject::connect(this, SIGNAL(chatEnd()), manager, SLOT(chatEnd()));
	}

	/**
	* destructor
	*/
	virtual ~Controler()
	{

	}


	/**
	* gets commands from cin and executes proper functions
	*/
	void run() override {
		string inCommand;
		int commandIndex;
		bool runOk = true;

		cout << "commands: quit | connect | disconnect | signin | login | logout | users | chat | chatend | send | help" << endl;
		while (runOk) {
			cin >> inCommand;
			commandIndex = -1;
			for (int i = 0; i < COMMAND_COUNT; ++i) {
				if (!inCommand.compare(commands[i])) {
					commandIndex = i;
					break;
				}
			}
			switch (commandIndex) {
			case QUIT: {
				runOk = false;
				break;
			}
			case CONNECT: {
				if (clientMngr->isConnected())
				{
				std::cout << "you are already connected" << std::endl;
				break;
				}
				string ipaddr;
				quint16 port = 0;

				cout << "Write host address: ";
				cin >> ipaddr;
				cout << "Write host port: ";
				cin >> port;
				emit serverConnect(QString(ipaddr.c_str()), port);
				break;
			}
			case DISCONNECT: {
				if (!clientMngr->isConnected())
				{
				std::cout << "you are not connected - you cant disconnect" << std::endl;
				break;
				}
				emit disconnect();
				break;
			}
			case SIGNIN: {
				if (!clientMngr->isConnected())
				{
					std::cout << "you are not connected" << std::endl;
					break;
				}
				else if (clientMngr->isLoggedIn())
				{
					std::cout << "you are still logged in" << std::endl;
					break;
				}				
				string name, password;
				cout << "User name: ";
				cin >> name;
				cout << "User password: ";
				cin >> password;
				emit signIn(QString(name.c_str()), QString(password.c_str()));
				break;
			}
			case LOGIN: {
				if (!clientMngr->isConnected())
				{
					std::cout << "you are not connected" << std::endl;
					break;
				}
				else if (clientMngr->isLoggedIn())
				{
					std::cout << "you are already logged in" << std::endl;
					break;
				}
				string name, password;
				cout << "User name: ";
				cin >> name;
				cout << "User password: ";
				cin >> password;
				emit logIn(QString(name.c_str()), QString(password.c_str()));
				break;
			}
			case LOGOUT: {
				if (!clientMngr->isLoggedIn())
				{
					std::cout << "you are not logged in" << std::endl;
					break;
				}
				emit logOut();
				break;
			}
			case USERS: {
				if(!clientMngr->isLoggedIn())
				{
					std::cout << "you are not logged in" << std::endl;
					break;
				}
				emit getOnlineUsers();
				break;
			}
			case CHAT: {
				if (!clientMngr->isLoggedIn())
				{
					std::cout << "you are not logged in" << std::endl;
					break;
				}
				string partner;
				cout << "Name: ";
				cin >> partner;
				emit startCommunicationWith(QString(partner.c_str()));
				break;
			}
			case CHATEND: {
				if (!clientMngr->isChatting())
				{
					std::cout << "you are not chatting" << std::endl;
					break;
				}
				emit chatEnd();
				break;
			}
			case SEND: {
				if (!clientMngr->isLoggedIn())
				{
					std::cout << "you are not logged in" << std::endl;
					break;
				}
				string msg;
				getline(std::cin, msg);
				emit sendToMessenger(QString::fromStdString(msg));
				break;
			}
			case HELP: {
				cout << "commands: quit | connect | disconnect | signin | login | logout | users | chat | chatend | send | help" << endl;
				break;
			}
			default: {
				cout << "Unknown command " << inCommand << endl;
				break;
			}
			}
		}
		exit(0);
	}


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
};


#endif //MESSEC_CONTROLLER_H
