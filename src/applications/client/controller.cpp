

#include <iostream>
//#include <string>
#include <controller.h>

using namespace std;

	Controler::Controler(QObject *parent/* = 0*/, ClientManager* manager/* = 0*/) : QThread(parent), clientMngr(manager)
	{
		QObject::connect(this, SIGNAL(serverConnect(QString, quint16)), manager, SLOT(serverConnect(QString, quint16)));
		QObject::connect(this, SIGNAL(disconnect()), manager, SLOT(disconnect()));
		QObject::connect(this, SIGNAL(logOut()), manager, SLOT(logOut()));
		QObject::connect(this, SIGNAL(getOnlineUsers()), manager, SLOT(getOnlineUsers()));
		QObject::connect(this, SIGNAL(signIn(QString, QString)), manager, SLOT(signIn(QString, QString)));
		QObject::connect(this, SIGNAL(logIn(QString, QString)), manager, SLOT(logIn(QString, QString)));
		QObject::connect(this, SIGNAL(startCommunicationWith(QString)), manager, SLOT(startCommunicationWith(QString)));
		QObject::connect(this, SIGNAL(sendToMessenger(QString)), manager, SLOT(sendToMessenger(QString)));
		QObject::connect(this, SIGNAL(sendFile(QString)), manager, SLOT(sendFileSlot(QString)));
		QObject::connect(this, SIGNAL(chatEnd()), manager, SLOT(chatEnd()));
	}

	Controler::~Controler() {};

	void Controler::run(){
		string inCommand;
		int commandIndex;
		bool runOk = true;

		cout << "commands: quit | connect | disconnect | signin | login | logout | users | chat | chatend | send | file | help" << endl;
		while (runOk) {
			cin.clear();
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
				if (password.find('|') != string::npos || name.find('|') != string::npos) {
					std::cout << "User name or password contains | or #" << std::endl;
				}
				else {
					emit signIn(QString(name.c_str()), QString(password.c_str()));
				}
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
				if (password.find('|') != string::npos || name.find('|') != string::npos) {
					std::cout << "User name or password contains | or #" << std::endl;
				}
				else {
					emit logIn(QString(name.c_str()), QString(password.c_str()));
				}
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
				if (!clientMngr->isLoggedIn())
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
				if (clientMngr->isChatting())
				{
					std::cout << "you are already chatting" << std::endl;
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
				if (!clientMngr->isChatting())
				{
					std::cout << "you are not chattting now" << std::endl;
					break;
				}
				string msg;
				getline(std::cin, msg);
				emit sendToMessenger(QString::fromStdString(msg).trimmed());
				break;
			}
			case FILE: {
				if (!clientMngr->isChatting())
				{
					std::cout << "you are not chatting now" << std::endl;
					break;
				}
				string msg;
				getline(std::cin, msg);
				emit sendFile(QString::fromStdString(msg).trimmed());
				break;
			}
			case HELP: {
				cout << "commands: quit | connect | disconnect | signin | login | logout | users | chat | chatend | send | file | help" << endl;
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


