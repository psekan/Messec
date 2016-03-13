//
// Created by Peter on 13.03.2016.
//

#ifndef MESSEC_CONNECTIONERRORS_H
#define MESSEC_CONNECTIONERRORS_H

enum ConnectionErrors {
    CONNECTION_TIMEOUT,                 //Connection was lost.
    CONNECTION_SECURITY_COMPROMISED,    //Secured communication failed.
    CONNECTION_UNEXPECTED_BEHAVIOR      //Wrong format of message in communication protocol.
};

#endif //MESSEC_CONNECTIONERRORS_H
