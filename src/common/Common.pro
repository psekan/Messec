QT += core
QT -= gui
QT += network

CONFIG += c++11

TARGET = Common
TEMPLATE = lib
DEFINES += COMMON_LIBRARY

SOURCES += ipv4.cpp
HEADERS += ipv4.h\
        connectionErrors.h

unix {
    target.path = /usr/lib
    INSTALLS += target
}

