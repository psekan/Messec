#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "../common/ipv4.h"
#include "../server/serverManager.h"
#include <vector>
/*
TEST_CASE("Server tests") {
	std::string names[5] = { "name0", "name1", "name2", "name3", "name4"};
	std::string pw[5] = {"password0", "password1", "password2", "password3", "password4" };
	
	SECTION("Constructor") {
		//Otestuj vytvoreni s nezmyselnou cestou, s dobrou cestou ale neexistujucim suborom, aby ho vytvorilo,
		//a otvorenie dva krat tej istej db, ci bude obsahovat to co predtym
		CHECK_THROWS_AS(ServerManager nokServer("./a/b/c/d/db_doesnt_exist"), DatabaseAccessForbidden);
		CHECK_NOTHROW(ServerManager okServer("dbtest123456789ok"));
	}

	SECTION("User registration") {
		ServerManager myServer("test_database");
		CHECK(myServer.userRegistration("John", "a") == false);
		CHECK(myServer.userRegistration("Jack", "length7") == false);

		for (int i = 0; i < 5; ++i) {
			CHECK(myServer.userRegistration(names[i], pw[i]) == true);
		}
		CHECK(myServer.userRegistration(names[1], pw[1]) == false);
		CHECK(myServer.userRegistration(names[3], "somepassword") == false);

		std::string hundrNames[100];
		std::string hundrPswrd[100];
		for (int i = 0; i < 100; i++) {
			hundrNames[i] = "name" + std::to_string(i);
			hundrPswrd[i] = "password" + std::to_string(i);
			CHECK(myServer.userRegistration(hundrNames[i], hundrPswrd[i]) == true);
		}
		myServer.clearDatabase();
	}

	SECTION("User authentication") {
		ServerManager myServer("test_database");
		for (int i = 0; i < 5; ++i) {
			myServer.userRegistration(names[i], pw[i]);
		}
		CHECK(myServer.userAuthentication(names[4], pw[4]) == true);
		CHECK(myServer.userAuthentication(names[0], pw[0]) == true);
		CHECK(myServer.userAuthentication(names[2], pw[2]) == true);
		CHECK(myServer.userAuthentication("wrongLogin", pw[0]) == false);
		CHECK(myServer.userAuthentication(names[1], "wrongPassword") == false);
		myServer.clearDatabase();
	}

	SECTION("List of online users") {
		ServerManager myServer("test_database");
		for (int i = 0; i < 5; ++i) {
			myServer.userRegistration(names[i], pw[i]);
		}
		//login 1,3,4
		std::vector<std::string> users = myServer.getOnlineUsers();
		CHECK(users.size() == 3);
		CHECK((users.at(0)).compare(names[1]) == 0);
		CHECK((users.at(1)).compare(names[3]) == 0);
		CHECK((users.at(2)).compare(names[4]) == 0);

		myServer.clearDatabase();
	}
}

*/

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
