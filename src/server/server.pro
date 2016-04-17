QT += core
QT -= gui

linux-g++ | linux-g++-64 | linux-g++-32 {
    QMAKE_CXX = g++-4.8
    QMAKE_CC = gcc-4.8
}

CONFIG += c++11
QMAKE_CXXFLAGS += -std=c++0x

TARGET = server
CONFIG += console
QT += network
CONFIG -= app_bundle

TEMPLATE = lib
DEFINES += SERVER_LIBRARY

SOURCES += \
    serverManager.cpp \
    client.cpp \
    database.cpp \
    sqlite3.c
HEADERS += client.h \
    database.h \
    serverManager.h \
    sqlite3.h

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../common/release/ -lcommon -lmbedTLS
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../common/debug/ -lcommon -lmbedTLS
else:unix: LIBS += -L/usr/local/share/mbedtls/library/ -L/usr/local/share/mbedtls/library/ -pthread -L$$OUT_PWD/../common/ -lcommon -lmbedTLS

unix: INCLUDEPATH += /usr/local/share/mbedtls/include/
INCLUDEPATH += $$PWD/../common
DEPENDPATH += $$PWD/../common
