TEMPLATE = subdirs  

SUBDIRS += \
    Common \
    Server \
    Client \   
    ServerApplication \
    ClientApplication \
    Tests  \
      
Common.subdir  = src/common
Server.subdir = src/server
Client.subdir  = src/client
ServerApplication.subdir = src/applications/server
ClientApplication.subdir  = src/applications/client
Tests.subdir  = src/tests
    
Server.depends = Common
Client.depends = Common    
ServerApplication.depends = Server
ClientApplication.depends = Client
Tests.depends = Server Client 
