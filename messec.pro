TEMPLATE = subdirs  
      
CONFIG += c++11 
QMAKE_CXXFLAGS += -std=c++11

SUBDIRS += \
    common \
    server \
    client \   
    serverApplication \
    clientApplication \
    tests  \
      
common.subdir  = src/common
server.subdir = src/server
client.subdir  = src/client
serverApplication.subdir = src/applications/server
clientApplication.subdir  = src/applications/client
tests.subdir  = src/tests
    
server.depends = common
client.depends = common    
serverApplication.depends = server
clientApplication.depends = client
tests.depends = server client 
