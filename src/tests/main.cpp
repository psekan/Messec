#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "../common/ipv4.h"
#include "../server/database.h"
#include "../server/serverManager.h"
#include <vector>

TEST_CASE("Database tests") {
	SECTION("Constructor database") {
		CHECK_THROWS_AS(Database nokDb("./a/b/c/d/db_doesnt_exist.db"), DatabaseAccessForbidden);
		CHECK_NOTHROW(Database okDb("dbtest123456789ok.db"));
	}

	SECTION("Database write/read") {
		Database myDB("myDB_rw.db");
		myDB.insertUser(UserDatabaseRow("testname", "testpassword", "testsalt"));
		myDB.insertUser(UserDatabaseRow("testname2", "testpassword2", "testsalt2"));
		UserDatabaseRow row = myDB.getUser("testname2");
		CHECK(row.exists() == true);
		CHECK(row.getName().compare("testname2") == 0);
		CHECK(row.getPassword().compare("testpassword2") == 0);
		CHECK(row.getSalt().compare("testsalt2") == 0);
	}

	SECTION("Load database") {
		Database myDB("myDB_load.db");
		myDB.insertUser(UserDatabaseRow("testname", "testpassword", "testsalt"));
		myDB.insertUser(UserDatabaseRow("testname2", "testpassword2", "testsalt2"));
		myDB.~Database();
		Database myDB_open("myDB_load.db");
		UserDatabaseRow row_open = myDB_open.getUser("testname");
		CHECK(row_open.exists() == true);
		CHECK(row_open.getName().compare("testname") == 0);
		CHECK(row_open.getPassword().compare("testpassword") == 0);
		CHECK(row_open.getSalt().compare("testsalt") == 0);
	}

	SECTION("clear database") {
		Database myDB("myDB_clear.db");
		myDB.insertUser(UserDatabaseRow("testname", "testpassword", "testsalt"));
		myDB.insertUser(UserDatabaseRow("testname2", "testpassword2", "testsalt2"));
		UserDatabaseRow row = myDB.getUser("testname");
		CHECK(row.exists() == true);
		CHECK(row.getName().compare("testname") == 0);
		CHECK(row.getPassword().compare("testpassword") == 0);
		CHECK(row.getSalt().compare("testsalt") == 0);
		row = myDB.getUser("testname2");
		CHECK(row.exists() == true);
		CHECK(row.getName().compare("testname2") == 0);
		CHECK(row.getPassword().compare("testpassword2") == 0);
		CHECK(row.getSalt().compare("testsalt2") == 0);
		myDB.clearDatabase();
		row = myDB.getUser("testname");
		CHECK(row.exists() == false);
		CHECK(row.getName().compare("testname") != 0);
		CHECK(row.getPassword().compare("testpassword") != 0);
		CHECK(row.getSalt().compare("testsalt") != 0);
		row = myDB.getUser("testname2");
		CHECK(row.exists() == false);
		CHECK(row.getName().compare("testname2") != 0);
		CHECK(row.getPassword().compare("testpassword2") != 0);
		CHECK(row.getSalt().compare("testsalt2") != 0);
	}

	SECTION("database delete user") {
		Database myDB("myDB_deleteUser.db");
		myDB.insertUser(UserDatabaseRow("testname", "testpassword", "testsalt"));
		myDB.insertUser(UserDatabaseRow("testname2", "testpassword2", "testsalt2"));
		UserDatabaseRow row = myDB.getUser("testname2");
		CHECK(row.exists() == true);
		CHECK(row.getName().compare("testname2") == 0);
		CHECK(row.getPassword().compare("testpassword2") == 0);
		CHECK(row.getSalt().compare("testsalt2") == 0);
		myDB.removeUser("testname2");
		row = myDB.getUser("testname2");
		CHECK(row.exists() == false);
		CHECK(row.getName().compare("testname2") != 0);
		CHECK(row.getPassword().compare("testpassword2") != 0);
		CHECK(row.getSalt().compare("testsalt2") != 0);
	}
}


TEST_CASE("Server tests") {
		std::string names[5] = { "name0", "name1", "name2", "name3", "name4" };
		std::string pw[5] = { "password0", "password1", "password2", "password3", "password4" };

	SECTION("Constructor database") {
		CHECK_THROWS_AS(ServerManager nokserver("./a/b/c/d/db_doesnt_exist2.db"), DatabaseAccessForbidden);
		CHECK_NOTHROW(ServerManager nokserver("dbtest123456789ok2.db"));
		}

	SECTION("User registration") {
		ServerManager myServer("test_database1.db");
		CHECK(myServer.userRegistration("John", "a") == false);
		CHECK(myServer.userRegistration("Jack", "length7") == false);

		for (int i = 0; i < 5; ++i) {
			CHECK(myServer.userRegistration(names[i], pw[i]) == true);
		}
		CHECK(myServer.userRegistration(names[1], pw[1]) == false);
		CHECK(myServer.userRegistration(names[3], "somepassword") == false);
		myServer.clearDatabase();

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
		ServerManager myServer("test_database2.db");
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
		ServerManager myServer("test_database3.db");
		for (int i = 0; i < 5; ++i) {
			myServer.userRegistration(names[i], pw[i]);
		}
		Client* c1 = myServer.clientConnect(7001);
		Client* c3 = myServer.clientConnect(7002);
		Client* c4 = myServer.clientConnect(7003);
		myServer.clientLogIn(c1, names[1], pw[1]);
		myServer.clientLogIn(c3, names[3], pw[3]);
		myServer.clientLogIn(c4, names[4], pw[4]);

		std::vector<std::string> users = myServer.getOnlineUsers();
		CHECK(users.size() == 3);
		CHECK((users.at(0)).compare(names[1]) == 0);
		CHECK((users.at(1)).compare(names[3]) == 0);
		CHECK((users.at(2)).compare(names[4]) == 0);

		myServer.clientLogOut(c3);
		std::vector<std::string> users2 = myServer.getOnlineUsers();
		CHECK(users2.size() == 2);
		CHECK((users2.at(0)).compare(names[1]) == 0);
		CHECK((users2.at(1)).compare(names[4]) == 0);

		myServer.clientDisconnect(c1);
		std::vector<std::string> users3 = myServer.getOnlineUsers();
		CHECK(users3.size() == 1);
		CHECK((users3.at(0)).compare(names[4]) == 0);
		myServer.clientDisconnect(c3);
		myServer.clientDisconnect(c4);

		myServer.clearDatabase();
	}
}



TEST_CASE("Database") {
	CHECK_NOTHROW(Database database("test_database.db"));
	Database database("test_database.db");
	database.clearDatabase();
	CHECK(database.insertUser(UserDatabaseRow("Name", "Pass", "Salt")));
	CHECK(database.insertUser(UserDatabaseRow("Name1", "Pass1", "Salt1")));
	CHECK((database.getLastError() == nullptr));
	CHECK(!database.getUser("Name2").exists());
	UserDatabaseRow user = database.getUser("Name");
	CHECK(user.exists());
	CHECK((user.getName() == "Name"));
	CHECK((user.getPassword() == "Pass"));
	CHECK((user.getSalt() == "Salt"));
	CHECK(database.removeUser("Name"));
	CHECK(!database.removeUser("Name2"));
	CHECK(!database.getUser("Name").exists());
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
