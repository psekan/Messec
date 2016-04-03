#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "../common/ipv4.h"
#include "../server/database.h"
#include "../server/serverManager.h"
#include <vector>
#include "../client/messenger.h"

TEST_CASE("Database tests") {
	SECTION("Constructor database") {
		CHECK_THROWS_AS(Database nokDb("./a/b/c/d/db_nok.db"), DatabaseAccessForbidden);
		CHECK_NOTHROW(Database okDb("db_ok.db"));
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
		CHECK_THROWS_AS(ServerManager nokserver("./a/b/c/d/db_nok2.db"), DatabaseAccessForbidden);
		CHECK_NOTHROW(ServerManager nokserver("db_ok2.db"));
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

	SECTION("Kick user") {
		ServerManager myServer("test_database4.db");
		for (int i = 0; i < 5; ++i) {
			myServer.userRegistration(names[i], pw[i]);
		}
		Client* c2 = myServer.clientConnect(7010);
		Client* c0 = myServer.clientConnect(7020);
		Client* c3 = myServer.clientConnect(7030);
		myServer.clientLogIn(c2, names[2], pw[2]);
		myServer.clientLogIn(c0, names[0], pw[0]);
		myServer.clientLogIn(c3, names[3], pw[3]);

		std::vector<std::string> users = myServer.getOnlineUsers();
		CHECK(users.size() == 3);
		CHECK((users.at(0)).compare(names[2]) == 0);
		CHECK((users.at(1)).compare(names[0]) == 0);
		CHECK((users.at(2)).compare(names[3]) == 0);

		myServer.kickUser(names[0]);
		std::vector<std::string> users2 = myServer.getOnlineUsers();
		CHECK(users2.size() == 2);
		CHECK((users2.at(0)).compare(names[2]) == 0);
		CHECK((users2.at(1)).compare(names[3]) == 0);
		myServer.clearDatabase();
	}

	SECTION("delete user") {
		ServerManager myServer("test_database5.db");
		for (int i = 0; i < 5; ++i) {
			myServer.userRegistration(names[i], pw[i]);
		}
		CHECK(myServer.userRegistration(names[2], pw[2]) == false);
		myServer.removeUserFromDb(names[2]);
		CHECK(myServer.userRegistration(names[2], pw[2]) == true);
		myServer.clearDatabase();
	}
}

TEST_CASE("Encryption_Decryption") {
	SECTION("input == dec(enc(input))") {
		const unsigned char input[30] = { 'T','h','i','s','_','i','s','_','m','y','_','s','u','p','e','r','_','t','e','s','t','_','m','e','s','s','a','g','e','!' };
		const unsigned char key[32] = { '0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1' };
		const unsigned char iv[32] = { 'a','b','c','d','e','f','g','h','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1' };
		size_t inlen = 30;
		size_t ivlen = 32;
		unsigned char encrypted[30];
		unsigned char decrypted[30];
		unsigned char tag[16];
		Messenger obj;
		CHECK(obj.encrypt(input, inlen, encrypted, iv, ivlen, tag, key));
		CHECK(obj.decrypt(encrypted, inlen, decrypted, iv, ivlen, tag, key));
		CHECK(!memcmp(input, decrypted, inlen));
	}
	SECTION("test vector 1") {
		//source: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf Test Case 14
		unsigned char key[32] = {	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };
		unsigned char plaintext[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char iv[12] = {	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00 };
		unsigned char cryptotextResult[16] = {	0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
			0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18};
		unsigned char tagResult[16] = { 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 
			0x26, 0x5b, 0x98,0xb5, 0xd4, 0x8a, 0xb9, 0x19 };
		unsigned char cryptotext[16];
		unsigned char tag[16];
		CHECK(Messenger::encrypt(plaintext, 16, cryptotext, iv, 12, tag, key));
		CHECK(!memcmp(cryptotext, cryptotextResult, 16));
		CHECK(!memcmp(tag, tagResult, 16));
	}
	SECTION("test vector 2") {
		//source: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf Test Case 15
		unsigned char key[32] = {	0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
			0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
			0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
			0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };
		unsigned char plaintext[64] = { 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
			0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
			0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 
			0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
			0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
			0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
			0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
			0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55 };
		unsigned char iv[12] = {	0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 
			0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88	};
		unsigned char cryptotextResult[64] = {	0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 
			0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
			0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 
			0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
			0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 
			0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
			0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 
			0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad };
		unsigned char tagResult[16] = { 0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd, 
			0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c};
		unsigned char cryptotext[64];
		unsigned char tag[16];
		CHECK(Messenger::encrypt(plaintext, 64, cryptotext, iv, 12, tag, key));
		CHECK(!memcmp(cryptotext, cryptotextResult, 64));
		CHECK(!memcmp(tag, tagResult, 16));
	}

	SECTION("corrupted encrypted message") {
		unsigned char key[32] = {	0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
			0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
			0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
			0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };
		unsigned char plaintext[64] = { 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
			0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
			0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
			0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
			0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
			0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
			0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
			0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55 };
		unsigned char iv[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
			0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
		unsigned char cryptotext[64];
		unsigned char tag[16];
		unsigned char plaintext2[64];
		Messenger::encrypt(plaintext, 64, cryptotext, iv, 12, tag, key);
		cryptotext[42] = 0x42;
		CHECK(!Messenger::decrypt(cryptotext, 64, plaintext2, iv, 12, tag, key));
		CHECK(memcmp(plaintext, plaintext2, 64));
	}

	SECTION("corrupted tag") {
		unsigned char key[32] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
			0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
			0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
			0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };
		unsigned char plaintext[64] = { 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
			0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
			0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
			0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
			0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
			0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
			0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
			0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55 };
		unsigned char iv[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
			0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
		unsigned char cryptotext[64];
		unsigned char tag[16];
		unsigned char plaintext2[64];
		Messenger::encrypt(plaintext, 64, cryptotext, iv, 12, tag, key);
		tag[11] = 0xfa;
		CHECK(!Messenger::decrypt(cryptotext, 64, plaintext2, iv, 12, tag, key));
	}
}

TEST_CASE("Send/Receive message") {
	SECTION("send and receive") {
		unsigned char key[32] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
			0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
			0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
			0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };
		unsigned char iv[32] ={ 0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
			0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
			0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
			0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa};

		const char* messageForSend = "Magic test words!";
		unsigned char messageType = 21;
		size_t messageLength = strlen(messageForSend);

		uint32_t counterA = 0x1368f2;
		uint32_t counterB = 0xfa5372;
		Messenger first("first", 6888, key, iv, counterA, counterB);
		Messenger second("second", 6777, key, iv, counterB, counterA);

		unsigned char* bytesToSend = new unsigned char[messageLength + 21];
		CHECK(first.prepareMessageToSend(messageType, messageLength, (const unsigned char*)messageForSend, bytesToSend));
		CHECK(memcmp(messageForSend, bytesToSend, messageLength) != 0);

		unsigned char* receivedMessage = new unsigned char[messageLength];
		unsigned char receivedMessageType = 0;
		CHECK(second.parseReceivedMessage(bytesToSend, messageLength + 21, receivedMessageType, receivedMessage));
		CHECK(receivedMessageType == messageType);
		CHECK(memcmp(receivedMessage, messageForSend, messageLength) == 0);

		delete[] bytesToSend;
		delete[] receivedMessage;
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
