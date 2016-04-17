QT += core
QT -= gui

CONFIG += c++11

TARGET = tests
CONFIG += console
QT += network
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp
HEADERS += catch.hpp

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../server/release/ -lserver
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../server/debug/ -lserver
else:unix: LIBS += -L$$OUT_PWD/../server/ -lserver

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../client/release/ -lclient
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../client/debug/ -lclient
else:unix: LIBS += -L$$OUT_PWD/../client/ -lclient

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../common/release/ -lcommon
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../common/debug/ -lcommon
else:unix: LIBS += -L$$OUT_PWD/../common/ -lcommon

INCLUDEPATH += $$PWD/../server
DEPENDPATH += $$PWD/../server

INCLUDEPATH += $$PWD/../client
DEPENDPATH += $$PWD/../client

INCLUDEPATH += $$PWD/../common
DEPENDPATH += $$PWD/../common
