#!/usr/bin/env python

####################### BEGIN LICENSE BLOCK #############################
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for
# the specific language governing rights and limitations under the License.
#
# The Original Code is Weave Python Client.
#
# The Initial Developer of the Original Code is Mozilla Corporation.
# Portions created by the Initial Developer are Copyright (C) 2009 the Initial
# Developer. All Rights Reserved.
#
# Contributor(s):
#  Michael Hanson <mhanson@mozilla.com> (original author)
#  Gerry <nickel_chrome@exfio.org>
#
# Alternatively, the contents of this file may be used under the terms of either
# the GNU General Public License Version 2 or later (the "GPL"), or the GNU
# Lesser General Public License Version 2.1 or later (the "LGPL"), in which case
# the provisions of the GPL or the LGPL are applicable instead of those above.
# If you wish to allow use of your version of this file only under the terms of
# either the GPL or the LGPL, and not to allow others to use your version of
# this file under the terms of the MPL, indicate your decision by deleting the
# provisions above and replace them with the notice and other provisions
# required by the GPL or the LGPL. If you do not delete the provisions above, a
# recipient may use your version of this file under the terms of any one of the
# MPL, the GPL or the LGPL.
#
###################### END LICENSE BLOCK ############################

import os
import urllib
import urllib2
import httplib
import hashlib
import hmac
import logging
import unittest
import base64
import re
import json
import binascii
import string
import pprint

opener = urllib2.build_opener(urllib2.HTTPHandler)

############ WEAVE USER API ###############

def createUser(serverURL, userID, password, email, secret = None, captchaChallenge = None, captchaResponse = None):
	"""Create a new user at the given server, with the given userID, password, and email.

	If a secret is provided, or a captchaChallenge/captchaResponse pair, those will be provided
	as well.  Note that the exact new-user-authorization logic is determined by the server."""

	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")
	if email.find('"') >=0:
		raise ValueError("Weave email addresses may not contain the quote character")
	if secret and secret.find('"') >=0:
		raise ValueError("Weave secret may not contain the quote character")

	url = serverURL + "/user/1.0/%s/" % userID

	secretStr = ""
	captchaStr = ""
	if secret:
		secretStr = ''', "secret":"%s"''' % secret

	if captchaChallenge and captchaResponse:
		if secret:
			raise WeaveException("Cannot provide both a secret and a captchaResponse to createUser")
		captchaStr = ''', "captcha-challenge":"%s", "captcha-response":"%s"''' % (captchaChallenge, captchaResponse)

	payload = '''{"password":"%s", "email": "%s"%s%s}''' % (password, email, secretStr, captchaStr)

	req = urllib2.Request(url, data=payload)
	req.get_method = lambda: 'PUT'
	try:
		f = opener.open(req)
		result = f.read()
		if result != userID:
			raise WeaveException("Unable to create new user: got return value '%s' from server" % result)

	except urllib2.URLError, e:
		msg = ""
		try:
			msg = e.read()
		except:
			pass
		raise WeaveException("Unable to communicate with Weave server: " + str(e) + "; %s" % msg)


def checkNameAvailable(serverURL, userID):
	"""Returns a boolean for whether the given userID is available at the given server."""
	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")

	url = serverURL + "/user/1.0/%s/" % userID

	req = urllib2.Request(url)
	try:
		f = urllib2.urlopen(req)
		result = f.read()
		if result == "1":
			return False
		elif result == "0":
			return True
		else:
			raise WeaveException("Unexpected return value from server on name-availability request: '%s'" % result)
	except urllib2.URLError, e:
		raise WeaveException("Unable to communicate with Weave server: " + str(e))


def getUserStorageNode(serverURL, userID, password):
	"""Returns the URL representing the storage node for the given user.

	Note that in the 1.0 server implementation hosted by Mozilla, the password
	is not actually required for this call."""

	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")

	url = serverURL + "/user/1.0/%s/node/weave" % userID


	req = urllib2.Request(url)
	base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
	req.add_header("Authorization", "Basic %s" % base64string)

	try:
		f = opener.open(req)
		result = f.read()
		f.close()
		return result

	except urllib2.URLError, e:
		if str(e).find("404") >= 0:
			return serverURL
		else:
			raise WeaveException("Unable to communicate with Weave server: " + str(e))


def changeUserEmail(serverURL, userID, password, newemail):
	"""Change the email address of the given user."""

	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")
	if newemail.find('"') >=0:
		raise ValueError("Weave email addresses may not contain the quote character")

	url = serverURL + "/user/1.0/%s/email" % userID

	payload = newemail

	req = urllib2.Request(url, data=payload)
	base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
	req.add_header("Authorization", "Basic %s" % base64string)
	req.get_method = lambda: 'POST'
	try:
		f = opener.open(req)
		result = f.read()
		if result != newemail:
			raise WeaveException("Unable to change user email: got return value '%s' from server" % result)

	except urllib2.URLError, e:
		raise WeaveException("Unable to communicate with Weave server: %s" % e)



def changeUserPassword(serverURL, userID, password, newpassword):
	"""Change the password of the given user."""

	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")

	url = serverURL + "/user/1.0/%s/password" % userID

	payload = newpassword
	req = urllib2.Request(url, data=payload)
	base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
	req.add_header("Authorization", "Basic %s" % base64string)
	req.get_method = lambda: 'POST'
	try:

		f = opener.open(req)
		result = f.read()
		if result != "success":
			raise WeaveException("Unable to change user password: got return value '%s' from server" % result)

	except urllib2.URLError, e:
		raise WeaveException("Unable to communicate with Weave server: %s" % e)



def deleteUser(serverURL, userID, password):
	"""Delete the given user."""

	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")

	url = serverURL + "/user/1.0/%s/" % userID

	req = urllib2.Request(url)
	base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
	req.add_header("Authorization", "Basic %s" % base64string)
	req.get_method = lambda: 'DELETE'
	try:
		f = opener.open(req)
		result = f.read()

	except urllib2.URLError, e:
		msg = ""
		try:
			msg = e.read()
		except:
			pass
		raise WeaveException("Unable to communicate with Weave server: " + str(e) + "; %s" % msg)



def setUserProfile(serverURL, userID, profileField, profileValue):
	"""Experimental: Set a user profile field.	Not part of the 1.0 API."""

	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")

	url = serverURL + "/user/1.0/%s/profile" % userID

	payload = newpassword
	req = urllib2.Request(url, data=payload)
	base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
	req.add_header("Authorization", "Basic %s" % base64string)
	req.get_method = lambda: 'POST'
	try:
		f = opener.open(req)
		result = f.read()
		if result != "success":
			raise WeaveException("Unable to change user password: got return value '%s' from server" % result)

	except urllib2.URLError, e:
		raise WeaveException("Unable to communicate with Weave server: %s" % e)



def _buildOnePwAuthTokenRequest(userID, password):
	"""Build the get Auth Token request body"""
		
	logging.debug("_buildOnePwAuthTokenRequest()")

	quickStretchPW = PBKDF2(password, userID, iterations=1000).read(32)


def getOnePwAuthToken(serverURL, userID, password):
	"""Returns the auth token for the given user."""

	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")

	url = serverURL + "/account/login"

	payload = _buildOnePwAuthTokenRequest(userID, password)
	req = urllib2.Request(url, data=payload)
	req.get_method = lambda: 'POST'
	try:

		f = opener.open(req)
		result = f.read()
		if result != "success":
			raise WeaveException("Unable to get auth token: got return value '%s' from server" % result)

	except urllib2.URLError, e:
		raise WeaveException("Unable to communicate with token server: %s" % e)

	try:
		f = opener.open(req)
		result = f.read()
		f.close()
		return result

	except urllib2.URLError, e:
		if str(e).find("404") >= 0:
			return serverURL
		else:
			raise WeaveException("Unable to communicate with token server: " + str(e))


# User API v1.0 implementation

class WeaveRegistrationContext:

	@staticmethod
	def get_storage_url(rootServer, userID, password):
		return getUserStorageNode(rootServer, userID, password)


# OnePw implementation:
from PBKDF2 import PBKDF2
from M2Crypto.EVP import Cipher, RSA, load_key_string
import M2Crypto.m2

M2Crypto_Decrypt = 0
M2Crypto_Encrypt = 1

class WeaveAccountOnePwContext(object):
	"""Encapsulates the cryptographic context for the OnePw account and token server."""

	def __init__(self, username, password):
		self.username  = None
		self.password  = None
		self.authToken = None

