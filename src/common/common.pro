QT += core
QT -= gui
QT += network

CONFIG += c++11 
QMAKE_CXXFLAGS += -std=c++11

TARGET = common
TEMPLATE = lib
DEFINES += COMMON_LIBRARY

SOURCES += ipv4.cpp
HEADERS += ipv4.h\
        connectionErrors.h

unix {
    target.path = /usr/lib
    INSTALLS += target
}

