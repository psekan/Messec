QT += core
QT -= gui

CONFIG += c++11

TARGET = Tests
CONFIG += console
QT += network
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp
HEADERS += catch.hpp

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../server/release/ -lServer
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../server/debug/ -lServer
else:unix: LIBS += -L$$OUT_PWD/../server/ -lServer

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../client/release/ -lClient
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../client/debug/ -lClient
else:unix: LIBS += -L$$OUT_PWD/../client/ -lClient

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../common/release/ -lCommon
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../common/debug/ -lCommon
else:unix: LIBS += -L$$OUT_PWD/../common/ -lCommon

INCLUDEPATH += $$PWD/../server
DEPENDPATH += $$PWD/../server

INCLUDEPATH += $$PWD/../client
DEPENDPATH += $$PWD/../client

INCLUDEPATH += $$PWD/../common
DEPENDPATH += $$PWD/../common
