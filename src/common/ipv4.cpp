//
// Created by Peter on 12.03.2016.
//
#define _CRT_SECURE_NO_WARNINGS
#include "ipv4.h"
#include "stdio.h"

/**
 * Create IPv4 object from array of numbers in interval [0-255]
 */
IPv4::IPv4(unsigned char ip[4]) {
    this->ip[0] = ip[0];
    this->ip[1] = ip[1];
    this->ip[2] = ip[2];
    this->ip[3] = ip[3];
}

/**
 * Create IPv4 object from string in format X.X.X.X, where X is number in interval [0-255]
 * @exception WrongIPv4Format if string not contains IPv4 in correct format
 */
IPv4::IPv4(std::string ip) {
    for (unsigned int i = 0; i < ip.length(); ++i) {
        if (ip[i] != '.' && !isdigit(ip[i])) {
            throw WrongIPv4Format();
        }
    }
    int parts[4];
    int read = sscanf(ip.c_str(), "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]);
    if (read != 4 ||
        parts[0] > 255 || parts[0] < 0 ||
        parts[1] > 255 || parts[1] < 0 ||
        parts[2] > 255 || parts[2] < 0 ||
        parts[3] > 255 || parts[3] < 0) {
        throw WrongIPv4Format();
    }
    for (int i = 0; i < 4; ++i) {
        this->ip[i] = (unsigned char)parts[i];
    }
}

/**
 * Convert IPv4 object to string format
 * @return std::string IPv4 in format X.X.X.X, where X is number in interval [0-255]
 */
IPv4::operator std::string() const {
    return getString();
}

/**
 * Get IPv4 object in string representation
 * @return std::string IPv4 in format X.X.X.X, where X is number in interval [0-255]
 */
std::string IPv4::getString() const {
    char asString[16];
    sprintf(asString, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return std::string(asString);
}
