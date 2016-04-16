//
// Created by Peter on 12.03.2016.
//

#ifndef MESSEC_IPV4_H
#define MESSEC_IPV4_H

#include <string>
#include <QtCore/qglobal.h>

#if defined(COMMON_LIBRARY)
#  define COMMONSHARED_EXPORT Q_DECL_EXPORT
#else
#  define COMMONSHARED_EXPORT Q_DECL_IMPORT
#endif

class COMMONSHARED_EXPORT IPv4 {
    unsigned char ip[4];
public:
    IPv4(unsigned char ip[4]);
    IPv4(std::string ip);

    operator std::string() const;
    std::string getString() const;
};

class WrongIPv4Format : std::exception {};

#endif //MESSEC_IPV4_H
