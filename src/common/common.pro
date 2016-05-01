QT += core
QT -= gui
QT += network

CONFIG += c++11 
CONFIG += staticlib
QMAKE_CXXFLAGS += -std=c++11

TARGET = common
TEMPLATE = lib    

SOURCES += crypto.cpp
HEADERS += connectionErrors.h\
	messageTypes.h\
	crypto.h
    
win32:CONFIG(release, debug|release): LIBS += -lmbedTLS
else:win32:CONFIG(debug, debug|release): LIBS += -lmbedTLS
else:unix: LIBS += -L/usr/local/share/mbedtls/library/ -pthread -lmbedcrypto -ldl

unix {
    INCLUDEPATH += /usr/local/share/mbedtls/include/
    target.path = /usr/lib
    INSTALLS += target
}

