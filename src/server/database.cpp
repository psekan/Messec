//
// Created by Peter on 16.03.2016.
//

#include "database.h"

Database::Database(std::string filePath) {
	if (sqlite3_open(filePath.c_str(), &db) != SQLITE_OK) {
		throw DatabaseAccessForbidden();
	}

	char* sql = "CREATE TABLE IF NOT EXISTS USER("  \
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
	char* sql = "SELECT NAME, PASSWORD, SALT FROM USER WHERE NAME = ?;";
	sqlite3_stmt * stmt;
	sqlite3_prepare(db, sql, strlen(sql) + 1, &stmt, nullptr);
	sqlite3_bind_text(stmt, 1, userName.c_str(), userName.length(), nullptr);
	freeLastError();
	int ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (ret != SQLITE_ROW) return UserDatabaseRow();
	return UserDatabaseRow(
		(const char*)sqlite3_column_text(stmt, 0), 
		(const char*)sqlite3_column_text(stmt, 1), 
		(const char*)sqlite3_column_text(stmt, 2)
	);
}

bool Database::insertUser(UserDatabaseRow user) {
	char* sql = "INSERT INTO USER (NAME, PASSWORD, SALT) VALUES (?,?,?);";
	sqlite3_stmt * stmt;
	sqlite3_prepare(db, sql, strlen(sql) + 1, &stmt, nullptr);
	sqlite3_bind_text(stmt, 1, user.getName().c_str(), user.getName().length(), nullptr);
	sqlite3_bind_text(stmt, 2, user.getPassword().c_str(), user.getPassword().length(), nullptr);
	sqlite3_bind_text(stmt, 3, user.getSalt().c_str(), user.getSalt().length(), nullptr);
	freeLastError();
	int ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (ret == SQLITE_DONE);
}

bool Database::removeUser(std::string userName) {
	char* sql = "DELETE FROM USER WHERE NAME = ?;";
	sqlite3_stmt * stmt;
	sqlite3_prepare(db, sql, strlen(sql) + 1, &stmt, nullptr);
	sqlite3_bind_text(stmt, 1, userName.c_str(), userName.length(), nullptr);
	freeLastError();
	int ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (ret == SQLITE_DONE);
}

void Database::clearDatabase() {
	char* sql = "DELETE FROM USER;";
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
