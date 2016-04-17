QT += core
QT -= gui
QT += network

CONFIG += c++11

TARGET = clientApplication
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp   
        
win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../../client/release/ -lclient
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../../client/debug/ -lclient
else:unix: LIBS += -L$$OUT_PWD/../../client/ -lclient

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../../common/release/ -lcommon
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../../common/debug/ -lcommon
else:unix: LIBS += -L$$OUT_PWD/../../common/ -lcommon

INCLUDEPATH += $$PWD/../../client
DEPENDPATH += $$PWD/../../client
                                  
INCLUDEPATH += $$PWD/../../common
DEPENDPATH += $$PWD/../../common
