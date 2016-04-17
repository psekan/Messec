//
// Created by Peter on 16.03.2016.
//

#include "database.h"
#include <cstring>

Database::Database(std::string filePath) : lastError(nullptr) {
	if (sqlite3_open(filePath.c_str(), &db) != SQLITE_OK) {
		throw DatabaseAccessForbidden();
	}

	const char* sql = "CREATE TABLE IF NOT EXISTS USER("  \
		"NAME           TEXT PRIMARY KEY NOT NULL," \
		"PASSWORD       TEXT    NOT NULL," \
		"SALT           TEXT    NOT NULL);";

	freeLastError();
	if (sqlite3_exec(db, sql, nullptr, nullptr, &lastError) != SQLITE_OK) {
		throw DatabaseAccessForbidden();
	}
}

Database::~Database() {
	freeLastError();
	sqlite3_close(db);
}

UserDatabaseRow Database::getUser(std::string userName) {
	const char* sql = "SELECT NAME, PASSWORD, SALT FROM USER WHERE NAME = ?;";
	sqlite3_stmt * stmt;
	sqlite3_prepare(db, sql, (int)(strlen(sql) + 1), &stmt, nullptr);
	sqlite3_bind_text(stmt, 1, userName.c_str(), (int)userName.length(), nullptr);
	freeLastError();
	if (sqlite3_step(stmt) != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return UserDatabaseRow();
	}

	UserDatabaseRow user(
		(const char*)sqlite3_column_text(stmt, 0), 
		(const char*)sqlite3_column_text(stmt, 1), 
		(const char*)sqlite3_column_text(stmt, 2)
	);
	sqlite3_finalize(stmt);
	return user;
}

bool Database::insertUser(UserDatabaseRow user) {
	const char* sql = "INSERT INTO USER (NAME, PASSWORD, SALT) VALUES (?,?,?);";
	sqlite3_stmt * stmt;
	sqlite3_prepare(db, sql, strlen(sql), &stmt, 0);
	std::string name = user.getName();
	std::string password = user.getPassword();
	std::string salt = user.getSalt();
	sqlite3_bind_text(stmt, 1, name.c_str(), (int)name.length(), SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, password.c_str(), (int)password.length(), SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 3, salt.c_str(), (int)salt.length(), SQLITE_TRANSIENT);
	freeLastError();
	int ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (ret == SQLITE_DONE);
}

bool Database::removeUser(std::string userName) {
	if (!this->getUser(userName).exists()) {
		return false;
	}
	const char* sql = "DELETE FROM USER WHERE NAME = ?;";
	sqlite3_stmt * stmt;
	sqlite3_prepare(db, sql, (int)(strlen(sql) + 1), &stmt, nullptr);
	sqlite3_bind_text(stmt, 1, userName.c_str(), (int)userName.length(), nullptr);
	freeLastError();
	int ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (ret == SQLITE_DONE);
}

void Database::clearDatabase() {
	const char* sql = "DELETE FROM USER;";
	freeLastError();
	if (sqlite3_exec(db, sql, nullptr, nullptr, &lastError) != SQLITE_OK) {
		throw std::exception();
	}
}

char* Database::getLastError() const {
	return lastError;
}

void Database::freeLastError() {
	if (lastError != nullptr){
		sqlite3_free(lastError);
		lastError = nullptr;
	}
}
