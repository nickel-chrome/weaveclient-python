#!/usr/bin/env python

####################### BEGIN LICENSE BLOCK #############################
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2014, Gerry Healy <nickel_chrome@exfio.org>
#
# This file incorporates work covered by the following copyright and
# permission notice:
#
#     Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
#     The contents of this file are subject to the Mozilla Public License Version
#     1.1 (the "License"); you may not use this file except in compliance with the
#     License. You may obtain a copy of the License at http://www.mozilla.org/MPL/
#
#     Software distributed under the License is distributed on an "AS IS" basis,
#     WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for
#     the specific language governing rights and limitations under the License.
#
#     The Original Code is Weave Python Client.
#
#     The Initial Developer of the Original Code is Mozilla Corporation.
#     Portions created by the Initial Developer are Copyright (C) 2009 the Initial
#     Developer. All Rights Reserved.
#
#     Contributor(s):
#     Michael Hanson <mhanson@mozilla.com> (original author)
#
#     Alternatively, the contents of this file may be used under the terms of either
#     the GNU General Public License Version 2 or later (the "GPL"), or the GNU
#     Lesser General Public License Version 2.1 or later (the "LGPL"), in which case
#     the provisions of the GPL or the LGPL are applicable instead of those above.
#     If you wish to allow use of your version of this file only under the terms of
#     either the GPL or the LGPL, and not to allow others to use your version of
#     this file under the terms of the MPL, indicate your decision by deleting the
#     provisions above and replace them with the notice and other provisions
#     required by the GPL or the LGPL. If you do not delete the provisions above, a
#     recipient may use your version of this file under the terms of any one of the
#     MPL, the GPL or the LGPL.
#
###################### END LICENSE BLOCK ############################

import os
import urllib
import urllib2
import requests

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
import datetime
import time

from urlparse import urlparse

from cryptography.hazmat.primitives import interfaces as crypto_interfaces
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import openssl

from fxa.core import Client

from browserid import jwt, LocalVerifier
from browserid.crypto import RSKey
from browserid.utils import bundle_certs_and_assertion, unbundle_certs_and_assertion, get_assertion_info, to_int

from fxa_client.fxa_crypto import dumpCert, createAssertion, createBackedAssertion, verifyBackedAssertion

from weaveinclude import WeaveException, trim_str

opener = urllib2.build_opener(urllib2.HTTPHandler)

TEST_MODE = False


def set_test_mode(test_mode):
	TEST_MODE = test_mode

def get_test_mode():
	return TEST_MODE

############ TEST DATA ################
TEST_KEY_DATA = {
	"algorithm": "RS",
	"e": trim_str("65537", True),
	"n": trim_str("""209243035644587250401544600980086312241568079755560
				  305799762634866415404663608185897137992156763240716044
				  835079029321020920839266474885928107865975645564079502
				  981832839660437041327486507875095992587448154572518952
				  353171418459412971288178331981587134721539194774559879
				  419636721646390043268846144379060232150404309749170094
				  874344199116271093479336726912962005140109609562500491
				  986525845020604223869841300953848164692141191106673921
				  873690576182194792161074852303575862501654210649197729
				  323552815813234047825816132375936584216835454534542565
				  653603107918395618982740825322497898026112880305190321
				  00136717907495704416146033""", True),
	"d": trim_str("""144813408726849625653643872417928420042736216083631
				  365338050777875642820228684201103750368650599055635101
				  478320331002541250080208271684713080984437147807344767
				  333673987342698672253701047312063856078076291971645667
				  666856829379794530398368930584079949792710274461597455
				  648510959972463084861147970926362740889051327974425117
				  482063498794195113160448742236665194358741505749709381
				  644695552875442234994058219788340536697858322121222831
				  900226567432616987092016513571904641884936803536775772
				  144713996142675890723849665606850078394691041559842722
				  140634996306232264935562495882403578622375767344422019
				  12990977046205516997686321""", True),
}

############ WEAVE SYNC USER API ###############

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

		#trim unecessary trailing slash
		if result[len(result)-1] == '/': result = result[:len(result)-1]
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


# Weave Sync Legacy User API interface
class WeaveAccountLegacy(object):

	server   = None
	username = None
	password = None

	def init(self, server, username, password):
		self.server   = server
		self.username = username
		self.password = password

	def get_storage_url(self):
		return getUserStorageNode(self.server, self.username, self.password)


############ WEAVE SYNC FXA API ###############

def getSyncAuthToken(session, server, synckey, audience=None, keypair=None, certificate=None):
	# build browserid assertion then then request sync auth token from token server
	#
	# GET /1.0/sync/1.5
	# Host: token.services.mozilla.com
	# Authorization: BrowserID <assertion>

	if ( audience == None ):
		parsed_url = urlparse(server)
		audience = parsed_url.scheme + "://" + parsed_url.netloc
		
	if ( keypair == None ):
		if ( certificate != None ):
			raise WeaveException("certificate param is invalid without keypair!")
		
		keypair = create_fxa_keypair()

	pubkey, privkey = keypair

	#print "privkey:\n" + pprint.pformat(privkey.get_data())
	#print "pubkey:\n" + pprint.pformat(pubkey.get_data())
	
	if ( certificate == None ):
		certificate = session.sign_certificate(pubkey.get_data())

	#print "certificate:\n" + pprint.pformat(certificate)
	logging.debug("certificate:\n" + pprint.pformat(decode_certificate(certificate)))
	
	assertion = build_assertion(keypair, certificate, audience)
	#assertion = build_assertion(keypair, certificate, audience, new_style=False)

	#print "browserid assertion:\n" + pprint.pformat(assertion)
	logging.debug("browserid assertion:\n" + pprint.pformat(get_assertion_info(assertion)))
	
	if not verify_assertion(audience, assertion, local=False):
		raise WeaveException("Failed to verify assertion for audience '%s'" % audience)

	client_state = build_client_state_header(synckey)
	logging.debug("clientstate: %s" % client_state)

	url = server + "/1.0/sync/1.5"

	logging.debug("token server: " + url)
	
	headers = {
		'Content-Type': "application/json",
		'Authorization': "BrowserID %s" % assertion,
		'X-Client-State': client_state,
	}

	res = requests.get(url, headers=headers)

	if res == None:
		raise WeaveException("Request failed, response object is empty")
	
	#raise error for 4XX and 5XX status codes
	res.raise_for_status()

	logging.debug("response status: %s, content: %s" % (res.status_code, res.text))
	
	return res.json()


def getFxASession(server, username, password, fetch_keys=False):
	client  = Client(server)
	session = client.login(username, password, keys=fetch_keys)
	return session


def build_assertion(keypair, certificate, audience, exp=None, new_style=True):
	"""
	Generate a new assertion for the given email address.

	This method lets you generate BrowserID assertions. Called with just
	an email and audience it will generate an assertion from
	login.persona.org.
	"""
	logging.debug("build_assertion()")

	#Default expiry to 5 minutes
	if exp is None:
		exp = int((time.time() + (5*60)) * 1000)

	pubkey, privkey = keypair

	#TODO - verify keypair matches certificate

	# Generate the assertion, signed with email's public key.
	assertion = {
		"exp": exp,
		"aud": audience,
	}
	assertion = jwt.generate(assertion, privkey.get_key())

	#print "assertion:\n" + assertion

	# Combine them into a BrowserID bundled assertion.
	return bundle_certs_and_assertion([certificate], assertion, new_style)

def verify_assertion(audience, assertion, local=True):

	if local:

		v = LocalVerifier(["*"], warning=False)
		result = v.verify(assertion)

	else:
		url		= "https://verifier.accounts.firefox.com/v2"
		payload = json.dumps({"audience": audience, "assertion": assertion})

		req = urllib2.Request(url, data=payload)
		req.add_header("Content-Type", "application/json")
		req.get_method = lambda: 'POST'

		try:
			f = opener.open(req)
			result = json.loads(f.read())
			f.close()

		except urllib2.URLError, e:
			raise WeaveException("FxA sync auth token request failed: " + str(e) + " " + e.read())

	if (result['status'] == 'okay'):
		return True
	else:
		logging.debug(pprint.pformat(result))
		return False


def build_client_state_header(synckey):
	m = hashlib.sha256()
	m.update(synckey)
	client_state = binascii.hexlify(m.digest()[:16])
	return client_state

	
def decode_certificate(cert, include_sig=False):
	logging.debug("decode_certificate()")
	
	pieces = cert.split(".")

	for i in range(len(pieces)):
		#print pprint.pformat(pieces[i])
		if (len(pieces[i]) % 3) > 0:
			pieces[i] = pieces[i] + (3 - len(pieces[i]) %3) * "="
		
	header = json.loads(base64.decodestring(pieces[0]))
	payload = json.loads(base64.decodestring(pieces[1]))

	if include_sig:
		signature = pieces[2]
		return header, payload, signature
	else:
		return header, payload
		

def rsa_to_jwt_data(key):

	if isinstance(key, crypto_interfaces.RSAPublicKeyWithNumbers):
		pubkey_numbers = key.public_numbers()
		jwt_data = {
			"algorithm": "RS",
			"n": str(pubkey_numbers.n),
			"e": str(pubkey_numbers.e),
		}

	elif isinstance(key, crypto_interfaces.RSAPrivateKeyWithNumbers):
		privkey_numbers = key.private_numbers()
		pubkey_numbers = privkey_numbers.public_numbers
		jwt_data = {
			"algorithm": "RS",
			"n": str(pubkey_numbers.n),
			"e": str(pubkey_numbers.e),
			"d": str(privkey_numbers.d),
		}

	else:
		raise WeaveException("Key '%s' not recognised" % key.__name__)

	return jwt_data


def rsa_to_jwt_key(key, digest_size=None):
	return jwt_data_to_jwt_key(rsa_to_jwt_data(key), digest_size)
	
def jwt_data_to_jwt_key(data, digest_size=None):

	if digest_size == None:
		digest_size = 256

	if data['algorithm'] == "RS":
		if digest_size == 256:
			jwt_key = jwt.RS256Key(data)

		else:
			raise WeaveException("Digest size '%s' not recognised" % digest_size)

	elif data['algorithm'] == "DS":
		if digest_size == 256:
			jwt_key = jwt.DS256Key(data)

		else:
			raise WeaveException("Digest size '%s' not recognised" % digest_size)
		
	return jwt_key


def create_fxa_keypair():

	if TEST_MODE:
		jwt_data = TEST_KEY_DATA
		jwt_privkey = JWTKey(jwt_data)
		if jwt_data['algorithm'] == "RS":
			del jwt_data['d']
		elif jwt_data['algorithm'] == "DS":
			del jwt_data['x']
		else:
			raise WeaveException("Algorithm '%s' not recongisied" % jwt_data['algorithm'])

		jwt_pubkey = JWTKey(jwt_data)

	else:
		# generate an RSA key pair
		privkey = rsa.generate_private_key(65537, 2048, openssl.backend)
		pubkey = privkey.public_key()
		
		#Convert to JWT
		jwt_pubkey  = JWTKey(pubkey)
		jwt_privkey = JWTKey(privkey)


	return jwt_pubkey, jwt_privkey


class JWTKey(object):

	jwt_data = None
	jwt_key  = None
	
	def __init__(self, key):
		logging.debug("JWTKey()")
		
		if (isinstance(key, crypto_interfaces.RSAPublicKeyWithNumbers)
			or isinstance(key, crypto_interfaces.RSAPrivateKeyWithNumbers)):
		
			self.jwt_data = rsa_to_jwt_data(key)
		
		elif isinstance(key, dict) and "algorithm" in key:
			self.jwt_data = key
		
		else:
			raise WeaveException("Invalid key '%s'" % type(key))
	
		self.jwt_key = jwt_data_to_jwt_key(self.jwt_data)


	def get_data(self):
		return self.jwt_data

	
	def get_key(self):
		return self.jwt_key


# Weave Sync FxA account interface
class WeaveAccountFxA(object):
	"""Encapsulates the cryptographic context for the OnePw account and token server."""

	account_server = None
	token_server   = None
	username       = None
	password       = None
	synckey        = None
	client         = None
	session        = None
	session_keys   = False

	def init(self, account_server, token_server, username, password):
		logging.debug("init()")
		
		self.account_server = account_server
		self.token_server   = token_server
		self.username       = username
		self.password       = password
		self.client         = Client(account_server)

	def get_session(self, keys=False):

		if (self.session == None or (keys and not session_keys)):
			if (self.session != None):
				session.destroy_session()
			
			self.session = self.client.login(self.username, self.password, keys=keys)
			self.session_keys = keys
			
		return self.session

		
	def get_auth_token(self, audience=None, keypair=None, certificate=None, synckey=None):
		if synckey == None:
			synckey = self.get_synckey()

		#get_session() must come after get_synckey() to make sure we have the same session object
		session = self.get_session()
		
		return getSyncAuthToken(session, self.token_server, synckey, audience=audience, keypair=keypair, certificate=certificate)


	def get_synckey(self):
		if self.synckey == None:			
			self.synckey = self.get_session(True).fetch_keys()[1]

		return self.synckey


############ MAIN ###############
# Begin main: If you're running in library mode, none of this matters.

if __name__ == "__main__":

	import sys
	from optparse import OptionParser

	# process arguments
	parser = OptionParser()
	parser.add_option("-s", "--account-server", help="account server url if you are not using defaults", dest="account_server")
	parser.add_option("-t", "--token-server", help="sync token server url if you are not using defaults", dest="token_server")
	parser.add_option("-u", "--user", help="username", dest="username")
	parser.add_option("-p", "--password", help="password (sent securely to server)", dest="password")
	parser.add_option("-K", "--credentialfile", help="get username and password from this credential file (as name=value lines)", dest="credentialfile")
	parser.add_option("-a", "--authenticate", help="get weave sync v6 authentication token", action="store_true", dest="authenticate")    
	parser.add_option("-v", "--verbose", help="print verbose logging", action="store_true", dest="verbose")
	parser.add_option("-l", "--log-level", help="set log level (critical|error|warn|info|debug)", dest="loglevel")
	parser.add_option("", "--test-mode", help="use test data", action="store_true", dest="testmode")


	(options, args) = parser.parse_args()

	if options.credentialfile:
		if options.username:
			print "The 'username' option must not be used when a credential file is provided."
			sys.exit(1)
		if options.password:
			print "The 'password' option must not be used when a credential file is provided."
			sys.exit(1)
		try:
			credFile = open(options.credentialfile, "r")
			for line in credFile:
				if len(line) and line[0] != '#':
					key, value = line.split('=', 1)
					key = key.strip()
					if key == 'username':
						options.username = value.strip()
					elif key == 'password':
						options.password = value.strip()
		except Exception, e:
			import traceback
			traceback.print_exc(e)
			print e
			sys.exit(1)

	if options.testmode:
		TEST_MODE = True
		
	if options.authenticate:
		if not ( options.username and options.password ):
			print "username and password are required arguments. Use -h for help."
			sys.exit(1)
	else:
		if not ( options.username and options.password ):
			print "username and password are required arguments. Use -h for help."
			sys.exit(1)

	if options.loglevel:
		logging.basicConfig(level = str.upper(options.loglevel))
	elif options.verbose:
		logging.basicConfig(level = logging.DEBUG)
	else:
		logging.basicConfig(level = logging.ERROR)

	if options.account_server:
		account_server = options.server
	else:
		account_server="https://api.accounts.firefox.com"

	if options.token_server:
		token_server = options.token_server
	else:
		token_server="https://token.services.mozilla.com"

	weaveAccount = WeaveAccountFxA()
	weaveAccount.init(account_server, token_server, options.username, options.password)

    
	# Now do what the user asked for

	if options.authenticate:

		print "Getting FxA sync auth token"
		token = weaveAccount.get_auth_token()
		print pprint.pformat(token)
			
	else:
		print "No command provided: use -h for help"

