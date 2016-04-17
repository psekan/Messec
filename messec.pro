TEMPLATE = subdirs  

linux-g++ | linux-g++-64 | linux-g++-32 {
    QMAKE_CXX = g++-4.8
    QMAKE_CC = gcc-4.8
}

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
