QT += core
QT -= gui
QT += network

CONFIG += c++11

TARGET = Client
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = lib
DEFINES += CLIENT_LIBRARY

SOURCES += messenger.cpp \
           clientManager.cpp      
HEADERS += messenger.h\
           clientManager.h
        
win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../common/release/ -lCommon -lmbedTLS
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../common/debug/ -lCommon -lmbedTLS
else:unix: LIBS += -L$$OUT_PWD/../common/ -lCommon -lmbedTLS

INCLUDEPATH += $$PWD/../common
DEPENDPATH += $$PWD/../common
