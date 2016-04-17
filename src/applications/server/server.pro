QT += core
QT -= gui   
QT += network

CONFIG += c++11  
QMAKE_CXXFLAGS += -std=c++11

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
