QT += core
QT -= gui
QT += network

CONFIG += c++11 
CONFIG += staticlib

TARGET = common
TEMPLATE = lib    

SOURCES += ipv4.cpp
HEADERS += ipv4.h\
        connectionErrors.h

unix {
    target.path = /usr/lib
    INSTALLS += target
}

