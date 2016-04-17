QT += core
QT -= gui   
QT += network

CONFIG += c++11

TARGET = ServerApplication
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../../server/release/ -lServer
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../../server/debug/ -lServer
else:unix: LIBS += -L$$OUT_PWD/../../server/ -lServer

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../../common/release/ -lCommon
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../../common/debug/ -lCommon
else:unix: LIBS += -L$$OUT_PWD/../../common/ -lCommon

INCLUDEPATH += $$PWD/../../server
DEPENDPATH += $$PWD/../../server
                                         
INCLUDEPATH += $$PWD/../../common
DEPENDPATH += $$PWD/../../common