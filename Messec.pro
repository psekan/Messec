TEMPLATE = subdirs  

SUBDIRS += \
    Server \
    Client \
    Tests  \
    Common
    
Server.subdir = src/server
Client.subdir  = src/client
Tests.subdir  = src/tests
Common.subdir  = src/common
    
Server.depends = Common
Client.depends = Common
Tests.depends = Server Client 
