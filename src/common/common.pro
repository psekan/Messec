QT += core
QT -= gui
QT += network

linux-g++ | linux-g++-64 | linux-g++-32 {
    QMAKE_CXX = g++-4.8
    QMAKE_CC = gcc-4.8
}

CONFIG += c++11 
QMAKE_CXXFLAGS += -std=c++0x

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

