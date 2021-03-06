﻿//
// Created by Peter on 16.03.2016.
//

#ifndef MESSEC_DATABASE_H
#define MESSEC_DATABASE_H

#include <string>
#include "sqlite3.h"
#include  <qmutex.h>

class WrongDatabasePassword : public std::exception {};

class DatabaseAccessForbidden : public std::exception {};

class UserDatabaseRow
{
	bool m_exists;
	std::string name;
	std::string password;
	std::string salt;
	
public:
	UserDatabaseRow() : m_exists(false), name(""), password(""), salt("") {};
 	UserDatabaseRow(std::string name, std::string password, std::string salt) : m_exists(true), name(name), password(password), salt(salt) {};

	std::string getName() const
	{
		return name;
	}

	void setName(const std::string name)
	{
		this->name = name;
	}

	std::string getPassword() const
	{
		return password;
	}

	void setPassword(const std::string password)
	{
		this->password = password;
	}

	std::string getSalt() const
	{
		return salt;
	}

	void setSalt(const std::string salt)
	{
		this->salt = salt;
	}

	bool exists() const
	{
		return m_exists;
	}
};

class Database
{
	char* lastError;
	sqlite3 *db;
	mutable QMutex mutex;
	
	void freeLastError();

	/**
	* Get user row from database
	* @param std::string user name
	* @return UserDatabaseRow
	*/
	UserDatabaseRow getUserWithoutMutex(std::string userName);
public:

	/**
	 * Constructor for open sqlite database with password 
	 * @exception DatabaseAccessForbidden if cannot read or create database
	 */
	Database(std::string filePath);

	/**
	 * Close database
	 */
	~Database();

	/**
	 * Get user row from database
	 * @param std::string user name
	 * @return UserDatabaseRow
	 */
	UserDatabaseRow getUser(std::string userName);

	/**
	 * Insert new user to database
	 * @param UserDatabaseRow user
	 * @return bool false if insert fails
	 */
	bool insertUser(UserDatabaseRow user);


	/**
	 * Remove user from database
	 * @param std::string user name
	 * @return bool if command fails
	 */
	bool removeUser(std::string userName);

	/**
	 * Clear all database, remove all user
	 */
	void clearDatabase();

	/**
	 * Get last error message
	 * @return char* c-style string or nullptr
	 */
	char* getLastError() const;
};


#endif //MESSEC_DATABASE_H
