#include <QCoreApplication>
#include "controller.h"

int main(int argc, char *argv[])
{
	QCoreApplication application(argc, argv);

	Controler controller(&application);
	QObject::connect(&controller, SIGNAL(finished()), &application, SLOT(quit()));
	controller.start();
	return application.exec(); 
}
