QT += core
QT -= gui
QT += network

CONFIG += c++11

TARGET = ClientApplication
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp   
        
win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../../client/release/ -lClient
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../../client/debug/ -lClient
else:unix: LIBS += -L$$OUT_PWD/../../client/ -lClient

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../../common/release/ -lCommon
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../../common/debug/ -lCommon
else:unix: LIBS += -L$$OUT_PWD/../../common/ -lCommon

INCLUDEPATH += $$PWD/../../client
DEPENDPATH += $$PWD/../../client
                                  
INCLUDEPATH += $$PWD/../../common
DEPENDPATH += $$PWD/../../common