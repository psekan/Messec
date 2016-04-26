//
// Created by Peter on 18.04.2016.
//

#ifndef MESSEC_CONTROLLER_H
#define MESSEC_CONTROLLER_H

#include <qglobal.h>
#include <iostream>
#include <QThread>
#include <clientManager.h>
#define  COMMAND_COUNT 8

using namespace std;

class Controler : public QThread
{
	Q_OBJECT
	enum commandsEnum { QUIT, CONNECT, DISCONNECT, SIGNIN, LOGIN, LOGOUT, USERS, HELP };
	string commands[COMMAND_COUNT] = { "quit", "connect", "disconnect","signin", "login", "logout", "users", "help" };

public:
	/**
	* constructor
	*/
	Controler(QObject *parent = 0) : QThread(parent){}

	/**
	* destructor
	*/
	virtual ~Controler(){}

	/**
	* gets commands from cin and executes proper functions
	*/
	void run() override {
		ClientManager clientMngr(this);
		string inCommand;
		int commandIndex;
		bool runOk = true;
		cout << "commands: quit | connect | disconnect | signin | login | logout | users | help" << endl;
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
				if (clientMngr.isConnected())
				{
				std::cout << "you are already connected" << std::endl;
				break;
				}
				string ipaddr;
				int port = 0;

				cout << "Write host address: ";
				cin >> ipaddr;
				cout << "Write host port: ";
				cin >> port;
				clientMngr.signalconnect(QString(ipaddr.c_str()), port);
				break;
			}
			case DISCONNECT: {
				if (!clientMngr.isConnected())
				{
				std::cout << "you are not connected - you cant disconnect" << std::endl;
				break;
				}
				clientMngr.disconnect();
				break;
			}
			case SIGNIN: {
				if (!clientMngr.isConnected())
				{
					std::cout << "you are not connected" << std::endl;
					break;
				}
				else if (clientMngr.isLoggedIn())
				{
					std::cout << "you are still logged in" << std::endl;
					break;
				}				
				string name, password;
				cout << "User name: ";
				cin >> name;
				cout << "User password: ";
				cin >> password;
				clientMngr.signIn(QString(name.c_str()), QString(password.c_str()));
				break;
			}
			case LOGIN: {
				if (!clientMngr.isConnected())
				{
					std::cout << "you are not connected" << std::endl;
					break;
				}
				else if (clientMngr.isLoggedIn())
				{
					std::cout << "you are already logged in" << std::endl;
					break;
				}
				string name, password;
				cout << "User name: ";
				cin >> name;
				cout << "User password: ";
				cin >> password;
				clientMngr.logIn(QString(name.c_str()), QString(password.c_str()));
				break;
			}
			case LOGOUT: {
				if (!clientMngr.isLoggedIn())
				{
					std::cout << "you are not logged in" << std::endl;
					break;
				}
				clientMngr.logOut();
				break;
			}
			case USERS: {
				if(!clientMngr.isLoggedIn())
				{
					std::cout << "you are not logged in" << std::endl;
					break;
				}
				clientMngr.getOnlineUsers();
				break;
			}
			case HELP: {
				cout << "commands: quit | connect | disconnect | signin | login | logout | users | help" << endl;
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

};


#endif //MESSEC_CONTROLLER_H
