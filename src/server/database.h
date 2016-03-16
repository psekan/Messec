//
// Created by Peter on 16.03.2016.
//

#ifndef MESSEC_DATABASE_H
#define MESSEC_DATABASE_H

#include <string>

class WrongDatabasePassword : public std::exception {};

class DatabaseAccessForbidden : public std::exception {};

class UserDatabaseRow
{
	std::string name;
	std::string password;
	std::string salt;
public:
	UserDatabaseRow(std::string name, std::string password, std::string salt) : name(name), password(password), salt(salt) {};

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
};

class Database
{
public:

	/**
	 * Constructor for open sqlite database with password 
	 * If database file not exists create new
	 * @exception WrongDatabasePassword if password is incorrect
	 * @exception DatabaseAccessForbidden if cannot read or create database
	 */
	Database(std::string filePath, std::string password);

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
};


#endif //MESSEC_DATABASE_H
