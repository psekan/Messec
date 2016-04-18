#include <QCoreApplication>
#include "serverManager.h"
#include <iostream>

using namespace std;

int main(int argc, char *argv[])
{
	QCoreApplication application(argc, argv);

	ServerManager server("database.db", (qint16)8081, 2048, &application);
	server.start();
	std::cout << "Started" << std::endl;

	QObject::connect(&server, SIGNAL(finished()), &application, SLOT(quit()));
	return application.exec(); 
}
