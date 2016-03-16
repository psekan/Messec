#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "../common/ipv4.h"

TEST_CASE("Server tests") {
	//TODO Jakub
	SECTION("Constructor") {
		//Otestuj vytvoreni s nezmyselnou cestou, s dobrou cestou ale neexistujucim suborom, aby ho vytvorilo,
		//a otvorenie dva krat tej istej db, ci bude obsahovat to co predtym
	}

	SECTION("User registration") {

	}

	SECTION("User authentication") {

	}

	SECTION("List of online users") {

	}
}

TEST_CASE("IPv4") {
    SECTION("Wrong format in string constructor") {
        CHECK_THROWS_AS(IPv4("text"), WrongIPv4Format);
        CHECK_THROWS_AS(IPv4("x.x.x.x"), WrongIPv4Format);
        CHECK_THROWS_AS(IPv4("0.0.0.x"), WrongIPv4Format);
        CHECK_THROWS_AS(IPv4("256.0.0.0"), WrongIPv4Format);
        CHECK_THROWS_AS(IPv4("0.0.256.0"), WrongIPv4Format);
        CHECK_THROWS_AS(IPv4("1.1.1"), WrongIPv4Format);
        CHECK_THROWS_AS(IPv4("1 .1.1.1"), WrongIPv4Format);
        CHECK_THROWS_AS(IPv4("1.1. 1.1"), WrongIPv4Format);
        CHECK_THROWS_AS(IPv4(" 1.1.1.1"), WrongIPv4Format);
        CHECK_THROWS_AS(IPv4("1.1.1.1 "), WrongIPv4Format);
        CHECK_THROWS_AS(IPv4("-1.1.1.1"), WrongIPv4Format);
        CHECK_THROWS_AS(IPv4("1.-1.1.1"), WrongIPv4Format);
    }

    SECTION("Correct format in string constructor") {
        CHECK_NOTHROW(IPv4("0.0.0.0"));
        CHECK_NOTHROW(IPv4("255.255.255.255"));
        CHECK_NOTHROW(IPv4("192.168.1.1"));
    }

    SECTION("Correct string conversion operator") {
        std::vector<std::string> ips = {
                "0.0.0.0",
                "1.1.1.1",
                "127.0.0.0",
                "192.168.1.1",
                "255.255.255.0",
                "255.255.255.255"
        };
        for (std::string ip : ips) {
            IPv4 iPv4(ip);
            std::string ipA = iPv4;
            std::string ipB = iPv4.getString();
            CHECK(ip == ipA);
            CHECK(ipA == ipB);
        }
    }
}
