//
// Created by Peter on 18.04.2016.
//

#ifndef MESSEC_CONTROLLER_H
#define MESSEC_CONTROLLER_H

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

				if (client->connect(ipaddr, port))
				{
					cout << "Successfully connected" << endl;
				}
				else
				{
					cout << "Connect fail" << endl;
				}
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
				if (client->signIn(name, password))
				{
					cout << "Successfully sign in" << endl;
				}
				else
				{
					cout << "Sign in fail" << endl;
				}
			}
			else if (command == "login") {
				string name, password;
				cout << "User name: ";
				cin >> name;
				cout << "User password: ";
				cin >> password;
				if (client->logIn(name, password))
				{
					cout << "Successfully log in" << endl;
				}
				else
				{
					cout << "Log in fail" << endl;
				}
			}
			else if (command == "logout") {
				client->logOut();
			}
			else if (command == "users") {
				cout << "Online users:" << endl;
				for (string user : client->getOnlineUsers())
				{
					cout << user << endl;
				}
			}
			else {
				cout << "Unknown command " << command << endl;
			}
		}
		exit(0);
	}
};


#endif //MESSEC_CONTROLLER_H
