//
// Created by Peter on 18.04.2016.
//

#ifndef MESSEC_CONTROLLER_H
#define MESSEC_CONTROLLER_H

#include <qglobal.h>
#include <iostream>
#include <QThread>
#include <clientManager.h>

using namespace std;

class Controler : public QThread
{
	Q_OBJECT
	ClientManager *client;
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
		string command;
		while (1) {
			cin >> command;
			if (command == "quit") {
				break;
			}
			else if (command == "connect") {
				string ipaddr;
				int port = 0;

				cout << "Write host address: ";
				cin >> ipaddr;
				cout << "Write host port: ";
				cin >> port;
				emit signalconnect(QString(ipaddr.c_str()), port);
			}
			else if (command == "disconnect") {
				client->disconnect();
			}
			else if (command == "signin") {
				string name, password;
				cout << "User name: ";
				cin >> name;
				cout << "User password: ";
				cin >> password;
				emit signIn(QString(name.c_str()), QString(password.c_str()));
			}
			else if (command == "login") {
				string name, password;
				cout << "User name: ";
				cin >> name;
				cout << "User password: ";
				cin >> password;
				emit logIn(QString(name.c_str()), QString(password.c_str()));
			}
			else if (command == "logout") {
				emit logOut();
			}
			else if (command == "users") {
				emit getOnlineUsers();
			}
			else {
				cout << "Unknown command " << command << endl;
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
