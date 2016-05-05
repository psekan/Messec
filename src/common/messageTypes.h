//
// Created by Peter on 18.04.2016.
//

#ifndef MESSEC_MESSAGETYPES_H
#define MESSEC_MESSAGETYPES_H

enum MessageTypes {
	MESSAGETYPE_LOGIN,
	MESSAGETYPE_LOGOUT,
	MESSAGETYPE_GET_ONLINE_USERS,
	MESSAGETYPE_SEND_PORT,
	MESSAGETYPE_GET_PARTNER,
	MESSAGETYPE_LOGIN_SUCCESS,
	MESSAGETYPE_LOGIN_FAIL,
	MESSAGETYPE_SIGNIN,
	MESSAGETYPE_SIGNIN_SUCCESS,
	MESSAGETYPE_SIGNIN_FAIL,
	MESSAGETYPE_PARTNER_INFO,
	MESSAGETYPE_PARTNER_NOT_ONLINE,
	MESSAGETYPE_MESSAGE,
	MESSAGETYPE_FILE,
	MESSAGETYPE_COMUNICATION_INIT
};

#endif //MESSEC_MESSAGETYPES_H
