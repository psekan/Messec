QT += core
QT -= gui   
QT += network

linux-g++ | linux-g++-64 | linux-g++-32 {
    QMAKE_CXX = g++-4.8
    QMAKE_CC = gcc-4.8
}

CONFIG += c++11  
QMAKE_CXXFLAGS += -std=c++0x

TARGET = serverApplication
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../../server/release/ -lserver
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../../server/debug/ -lserver
else:unix: LIBS += -L$$OUT_PWD/../../server/ -lserver

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../../common/release/ -lcommon
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../../common/debug/ -lcommon
else:unix: LIBS += -L$$OUT_PWD/../../common/ -lcommon

INCLUDEPATH += $$PWD/../../server
DEPENDPATH += $$PWD/../../server
                                         
INCLUDEPATH += $$PWD/../../common
DEPENDPATH += $$PWD/../../common
