QT += core
QT -= gui
QT += network

CONFIG += c++11 
QMAKE_CXXFLAGS += -std=c++0x

TARGET = client
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = lib
DEFINES += CLIENT_LIBRARY

SOURCES += messenger.cpp \
           clientManager.cpp      
HEADERS += messenger.h\
           clientManager.h
        
win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../common/release/ -lcommon -lmbedTLS
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../common/debug/ -lcommon -lmbedTLS
else:unix: LIBS += -L/usr/local/share/mbedtls/library/ -pthread -L$$OUT_PWD/../common/ -lcommon -lmbedTLS
                    
unix: INCLUDEPATH += /usr/local/share/mbedtls/include/
INCLUDEPATH += $$PWD/../common
DEPENDPATH += $$PWD/../common
