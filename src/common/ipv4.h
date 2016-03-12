//
// Created by Peter on 12.03.2016.
//

#ifndef MESSEC_IPV4_H
#define MESSEC_IPV4_H

#include <string>

class IPv4 {
    unsigned char ip[4];
public:
    IPv4(unsigned char ip[4]);
    IPv4(std::string ip);

    operator std::string() const;
    std::string getString() const;
};

class WrongIPv4Format : std::exception {};

#endif //MESSEC_IPV4_H
