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
		ClientManager *clientMngr;
	enum commandsEnum { QUIT, CONNECT, DISCONNECT, SIGNIN, LOGIN, LOGOUT, USERS, HELP };
	string commands[COMMAND_COUNT] = { "quit", "connect", "disconnect","signin", "login", "logout", "users", "help" };

public:

	Controler(QObject *parent = 0) : QThread(parent)
	{
		clientMngr = new ClientManager(this);
		QObject::connect(clientMngr, SIGNAL(finished()), this, SLOT(quit()));

		connect(this, SIGNAL(signalDisconnect()), clientMngr, SLOT(disconnect()));

		connect(this, SIGNAL(signalconnect(QString, int)), clientMngr, SLOT(signalconnect(QString, int)));
		connect(clientMngr, SIGNAL(signalconnected(bool)), this, SLOT(signalconnected(bool)));

		connect(this, SIGNAL(getOnlineUsers()), clientMngr, SLOT(getOnlineUsers()));
		connect(clientMngr, SIGNAL(getOnlineUsersResult(QStringList)), this, SLOT(getOnlineUsersResult(QStringList)));

		connect(this, SIGNAL(signIn(QString, QString)), clientMngr, SLOT(signIn(QString, QString)));
		connect(clientMngr, SIGNAL(signInResult(bool)), this, SLOT(signInResult(bool)));

		connect(this, SIGNAL(logIn(QString, QString)), clientMngr, SLOT(logIn(QString, QString)));
		connect(clientMngr, SIGNAL(logInResult(bool)), this, SLOT(logInResult(bool)));

		connect(this, SIGNAL(logOut()), clientMngr, SLOT(logOut()));

		clientMngr->start();
	}

	virtual ~Controler()
	{
		delete clientMngr;
	}

	void run() override {
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
				/*if (clientMngr->isConnected())         // pre testovanie zakomentovane
				{
				std::cout << "you are already connected" << std::endl;
				break;
				}*/
				string ipaddr;
				int port = 0;

				cout << "Write host address: ";
				cin >> ipaddr;
				cout << "Write host port: ";
				cin >> port;
				emit signalconnect(QString(ipaddr.c_str()), port);
				break;
			}
			case DISCONNECT: {
				/*if (!clientMngr->isConnected())         // pre testovanie zakomentovane
				{
				std::cout << "you are not connected - you cant disconnect" << std::endl;
				break;
				}*/
				emit signalDisconnect();
				break;
			}
			case SIGNIN: {
				/*if (!clientMngr->isConnected())         // pre testovanie zakomentovane
				{
				std::cout << "you are not connected" << std::endl;
				break;
				}*/
				string name, password;
				cout << "User name: ";
				cin >> name;
				cout << "User password: ";
				cin >> password;
				emit signIn(QString(name.c_str()), QString(password.c_str()));
				break;
			}
			case LOGIN: {
				/*if (clientMngr->isLoggedIn())         // pre testovanie zakomentovane
				{
					std::cout << "you are already logged in" << std::endl;
					break;
				}*/
				string name, password;
				cout << "User name: ";
				cin >> name;
				cout << "User password: ";
				cin >> password;
				emit logIn(QString(name.c_str()), QString(password.c_str()));
				break;
			}
			case LOGOUT: {
				/*if (!clientMngr->isLoggedIn())    // pre testovanie zakomentovane
				{
					std::cout << "you are not logged in" << std::endl;
					break;
				}*/
				emit logOut();
				break;
			}
			case USERS: {
				/*if(!clientMngr->isLoggedIn())    // pre testovanie zakomentovane
				{
					std::cout << "you are not logged in" << std::endl;
					break;
				}*/
				emit getOnlineUsers();
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
		clientMngr->exit(0);
		exit(0);
	}

signals:
	/**
	* connects client with server
	* @param Qstring addr ip of server to connect
	* @param int port number of port to connect
	*/
	void signalconnect(QString addr, int port);
	
	/**
	* disconnects client from server
	* clientManager is still running
	*/
	void signalDisconnect();

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
	* @param Qstring user name
	* @param Qstring password of user
	*/
	void signIn(QString userName, QString password);

	/**
	* Log in to the server with user name and password.
	* If log in is successful, new thread is created and callbacks can be immediately executed.
	* @param Qstring user name
	* @param Qstring password of user
	*/
	void logIn(QString userName, QString password);

	public slots:

	void signalconnected(bool isConnected)
	{
		if (isConnected)
		{
			cout << "Successfully connected" << endl;
		}
		else
		{
			cout << "Connect fail" << endl;
		}
	}

	void signInResult(bool result)
	{
		if (result)
		{
			cout << "Sign in successful" << endl;
		}
		else
		{
			cout << "Sign in fail" << endl;
		}
	}

	void logInResult(bool result)
	{
		if (result)
		{
			cout << "Log in successful" << endl;
		}
		else
		{
			cout << "Log in fail" << endl;
		}
	}

	void getOnlineUsersResult(QStringList users)
	{
		cout << "Online users:" << endl;
		for (QString user : users)
		{
			cout << user.toStdString() << endl;
		}
	}


};


#endif //MESSEC_CONTROLLER_H
