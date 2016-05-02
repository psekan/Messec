#include <QCoreApplication>
#include "controller.h"

int main(int argc, char *argv[])
{
	QCoreApplication application(argc, argv);

	ClientManager clientMngr(&application);
	clientMngr.start();

	Controler controller(&application, &clientMngr);
	QObject::connect(&controller, SIGNAL(finished()), &application, SLOT(quit()));
	controller.start();
	return application.exec(); 
}
