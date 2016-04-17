QT += core
QT -= gui

CONFIG += c++11

TARGET = Server
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

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../common/release/ -lCommon -lmbedTLS
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../common/debug/ -lCommon -lmbedTLS
else:unix: LIBS += -L$$OUT_PWD/../common/ -lCommon -lmbedTLS

INCLUDEPATH += $$PWD/../common
DEPENDPATH += $$PWD/../common
