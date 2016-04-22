//
// Created by Peter on 18.04.2016.
//

#ifndef MESSEC_CONTROLLER_H
#define MESSEC_CONTROLLER_H

#include <qglobal.h>
#include <iostream>
#include <QThread>
#include <clientManager.h>
#define  COMMAND_COUNT 7

using namespace std;

class Controler : public QThread
{
	Q_OBJECT
		ClientManager *client;
	enum commandsEnum { QUIT, CONNECT, DISCONNECT, SIGIN, LOGIN, LOGOUT, USERS };
	string commands[COMMAND_COUNT] = { "quit", "connect", "disconnect","signin", "login", "logout", "users" };

public:

	Controler(QObject *parent = 0) : QThread(parent)
	{
		client = new ClientManager(this);
		QObject::connect(client, SIGNAL(finished()), this, SLOT(quit()));

		connect(client, SIGNAL(signalconnected(bool)), this, SLOT(signalconnected(bool)));
		connect(this, SIGNAL(signalconnect(QString, int)), client, SLOT(signalconnect(QString, int)));

		connect(client, SIGNAL(getOnlineUsersResult(QStringList)), this, SLOT(getOnlineUsersResult(QStringList)));
		connect(this, SIGNAL(getOnlineUsers()), client, SLOT(getOnlineUsers()));

		connect(client, SIGNAL(signInResult(bool)), this, SLOT(signInResult(bool)));
		connect(this, SIGNAL(signIn(QString, QString)), client, SLOT(signIn(QString, QString)));

		connect(client, SIGNAL(logInResult(bool)), this, SLOT(logInResult(bool)));
		connect(this, SIGNAL(logIn(QString, QString)), client, SLOT(logIn(QString, QString)));

		connect(this, SIGNAL(logOut()), client, SLOT(logOut()));
		client->start();
	}

	virtual ~Controler()
	{
		delete client;
	}

	void run() override {
		string inCommand;
		int commandIndex;
		bool runOk = true;
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
				client->disconnect();
				break;
			}
			case SIGIN: {
				string name, password;
				cout << "User name: ";
				cin >> name;
				cout << "User password: ";
				cin >> password;
				emit signIn(QString(name.c_str()), QString(password.c_str()));
				break;
			}
			case LOGIN: {
				/*if (client->isLoggedIn())         // pre testovanie zakomentovane
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
				/*if (!client->isLoggedIn())    // pre testovanie zakomentovane
				{
					std::cout << "you are not logged in" << std::endl;
					break;
				}*/
				emit logOut();
				break;
			}
			case USERS: {
				/*if(!client->isLoggedIn())    // pre testovanie zakomentovane
				{
					std::cout << "you are not logged in" << std::endl;
					break;
				}*/
				emit getOnlineUsers();
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
	void signalconnect(QString addr, int port);

	/**
	* Log out user.
	* Thread will be stopped, no more callbacks will be executed.
	*/
	void logOut();

	/**
	* Get names of all online users.
	* @return std::vector<std::string> container of users names
	*/
	void getOnlineUsers();


	/**
	* Sign in new user.
	* @param std::string user name
	* @param std::string password of user
	* @return bool true if new user is successfully signed in
	*/
	void signIn(QString userName, QString password);

	/**
	* Log in to the server with user name and password.
	* If log in is successful, new thread is created and callbacks can be immediately executed.
	* @param std::string user name
	* @param std::string password of user
	* @return bool true if user is successfully logged in
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
			cout << "Successfully sign in" << endl;
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
			cout << "Successfully log in" << endl;
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
