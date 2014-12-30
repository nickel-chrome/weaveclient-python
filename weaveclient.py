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
import httplib
import requests

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
import hawk

from urlparse import urlparse

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from weaveinclude import WeaveException, parse_normalized_url
from weaveaccount import WeaveAccountLegacy, WeaveAccountFxA, TEST_MODE as WA_TEST_MODE


########################################
# Weave Sync HTTP auth implementation
########################################

class WeaveAuthBasic(object):

	def __init__(self, username, password):
		self.header_key = "Authorization"
		self.header_val = "Basic %s" % base64.encodestring('%s:%s' % (username, password))[:-1]

	def get_auth_header(self, method, url, data):
		return self.header_key, self.header_val


class WeaveAuthHawk(object):
	
	def __init__(self, id, key):
		self.header_key = "Authorization"
		
		self.id  = id
		self.key = key

		logging.debug("Hawk auth id: '%s', key: '%s'" % (self.id, self.key))


	def get_auth_header(self, method, url, data):
	
		creds = {
			'id': self.id,
			'key': self.key,
			'algorithm': "sha256",
		}

		hawk_header = hawk.client.header(url, method, {"credentials": creds, "ext": ""})

		if not self.verify_auth_header(method, url, data, hawk_header['field']):
			raise WeaveException("Hawk header invalid!")

		return self.header_key, hawk_header['field']


	def verify_auth_header(self, method, url, data, header):
		logging.debug("verify_auth_header()")

		parsed_url = parse_normalized_url(url)

		req = {
			'method': method,
			'url': url,
			'host': parsed_url['hostname'],
			'port': parsed_url['port'],
			'headers': {
				'authorization': header
			}
		}
		
		logging.debug("hawk auth request:\n" + pprint.pformat(req))

		credentials = {
			self.id.replace('=', ''): {
				'id': self.id,
				'key': self.key,
				'algorithm': 'sha256',
			}
		}

		logging.debug("hawk auth credentials:\n" + pprint.pformat(credentials))
		
		server = hawk.Server(req, lambda cid: credentials[cid])

		# This will raise a hawk.util.HawkException if it fails
		artifacts = server.authenticate({})

		#logging.debug("hawk auth artifacts:\n" + pprint.pformat(artifacts))

		return True

########################################
# Weave Sync storage API implementation
########################################

class WeaveStorageContext(object):
	"""An object that encapsulates a server and credentials, to simplify
	storage calls for the client."""

	api_version     = None
	
	storageUrl      = None
	storageAuth     = None

	def http_get(self, url):
		return storage_http_op("GET", url, withAuth=self.storageAuth)

	def put(self, collection, item, urlID=None, ifUnmodifiedSince=None):
		return add_or_modify_item(self.storageUrl, self.storageAuth, collection, item, urlID=urlID, ifUnmodifiedSince=ifUnmodifiedSince)

	def put_collection(self, collection, itemArray, ifUnmodifiedSince=None):
		return add_or_modify_items(self.storageUrl, self.storageAuth, collection, itemArray, ifUnmodifiedSince=ifUnmodifiedSince)

	def delete(self, collection, id, ifUnmodifiedSince=None):
		return delete_item(self.storageUrl, self.storageAuth, collection, id, ifUnmodifiedSince=ifUnmodifiedSince)

	def delete_collection(self, collection, idArray=None, params=None):
		return delete_items(self.storageUrl, self.storageAuth, collection, idArray=idArray, params=params)

	def delete_items_older_than(self, collection, timestamp):
		return delete_items_older_than(self.storageUrl, self.storageAuth, collection, timestamp)

	def delete_all(self):
		return delete_all(self.storageUrl, self.storageAuth)

	def get_collection_counts(self):
		return get_collection_counts(self.storageUrl, self.storageAuth)

	def get_collection_timestamps(self):
		return get_collection_timestamps(self.storageUrl, self.storageAuth)

	def get_collection_ids(self, collection, params=None, asJSON=True, outputFormat=None):
		return get_collection_ids(self.storageUrl, self.storageAuth, collection, params=params, asJSON=asJSON, outputFormat=outputFormat)

	def get(self, collection, id, asJSON=True):
		return get_item(self.storageUrl, self.storageAuth, collection, id, asJSON=asJSON)

	def get_collection(self, collection, asJSON=True):
		return get_items(self.storageUrl, self.storageAuth, collection, asJSON=asJSON)

	def get_quota(self):
		return get_quota(self.storageUrl, self.storageAuth)

	def get_meta(self):
		"""Returns an array of meta information. Storage version 5 only"""
		item = get_path(self.storageUrl, self.storageAuth, 'meta/global')
		return json.loads(item['payload'])

	def get_keys(self):
		"""Returns storage keys. Storage version 5 only"""
		item = get_path(self.storageUrl, self.storageAuth, 'crypto/keys')
		return json.loads(item['payload'])


class WeaveStorageV1_1(WeaveStorageContext):
	"""An object that encapsulates a server and credentials, to simplify
	storage calls for the client."""

	api_version = "1.1"

	def __init__(self, account, username, password):

		# Build storage url
		self.storageUrl  = account.get_storage_url() + "/%s/%s" % (self.api_version, username)

		# Instansiate HTTP auth
		self.storageAuth = WeaveAuthBasic(username, password)


class WeaveStorageV1_5(WeaveStorageContext):
	"""An object that encapsulates a server and credentials, to simplify
	storage calls for the client."""

	api_version = "1.5"
	
	def __init__(self, account):
		logging.debug("WeaveStorageV1_5()")
		
		token = account.get_auth_token()

		logging.debug("auth token\n:" + pprint.pformat(token))

		# Build storage url
		self.storageUrl  = token['api_endpoint']

		# Instansiate HTTP auth
		
		#IMPORTANT - ignore urlsafe base64 encoding of id and key. use id as-is and encode key as utf8
		hawk_id  = token['id']
		hawk_key = token['key'].encode('utf8')

		self.storageAuth = WeaveAuthHawk(hawk_id, hawk_key)


def storage_http_op(method, url, payload=None, asJSON=True, ifUnmodifiedSince=None, withConfirmation=None, withAuth=None, outputFormat=None):
	"""Generic HTTP helper function.  Sets headers and performs I/O, optionally
	performing JSON parsing on the result."""

	logging.debug("Storage request method: %s url: %s" % (method.upper(), url))
	
	if not payload == None:
		logging.debug("payload:\n" + payload)

	headers = {}
	if withAuth:
		key, value = withAuth.get_auth_header(method, url, payload)
		headers[key] = value
	if ifUnmodifiedSince:
		headers['X-If-Unmodified-Since'] = "%s" % ifUnmodifiedSince
	if withConfirmation:
		headers['X-Confirm-Delete'] = "true"
	if outputFormat:
		headers['Accept'] = outputFormat

	if len(headers) > 0:
		logging.debug("headers:\n" + pprint.pformat(headers))
	
	method = method.upper()

	res = None
	if method == 'GET':
		res = requests.get(url, headers=headers)
	elif method == 'POST':
		res = requests.post(url, payload=payload, headers=headers)
	elif method == 'PUT':
		res = requests.put(url, payload=payload, headers=headers)		
	elif method == 'DELETE':
		res = requests.delete(url, headers=headers)
	else:
		raise WeaveException("HTTP method '%s' not supported" % method)

	if res == None:
		raise WeaveException("Request failed, response object is empty")
	
	#raise error for 4XX and 5XX status codes
	res.raise_for_status()

	logging.debug("response status: %s, content: %s" % (res.status_code, res.text))
	
	if asJSON:
		return res.json()
	else:
		return res.text


def add_or_modify_item(storageServerURL, auth, collection, item, urlID=None, ifUnmodifiedSince=None):
	'''Adds the WBO defined in 'item' to 'collection'.	If the WBO does
	not contain a payload, will update the provided metadata fields on an
	already-defined object.

	Returns the timestamp of the modification.'''

	logging.debug("add_or_modify_item()")

	if urlID:
		url = storageServerURL + "/storage/%s/%s" % (collection, urllib.quote(urlID))
	else:
		url = storageServerURL + "/storage/%s" % (collection)
	if type(item) == str:
		itemJSON = item
	else:
		itemJSON = json.dumps(item, ensure_ascii=False)

	logging.debug("payload:\n" + pprint.pformat(itemJSON))
	
	return storage_http_op("PUT", url, itemJSON, asJSON=False, ifUnmodifiedSince=ifUnmodifiedSince, withAuth=auth)

def add_or_modify_items(storageServerURL, auth, collection, itemArray, ifUnmodifiedSince=None):
	'''Adds all the items defined in 'itemArray' to 'collection'; effectively
	performs an add_or_modifiy_item for each.

	Returns a map of successful and modified saves, like this:

	{"modified":1233702554.25,
	 "success":["{GXS58IDC}12","{GXS58IDC}13","{GXS58IDC}15","{GXS58IDC}16","{GXS58IDC}18","{GXS58IDC}19"],
	 "failed":{"{GXS58IDC}11":["invalid parentid"],
											 "{GXS58IDC}14":["invalid parentid"],
											 "{GXS58IDC}17":["invalid parentid"],
											 "{GXS58IDC}20":["invalid parentid"]}
	}
	'''
	logging.debug("add_or_modify_items()")

	url = storageServerURL + "/storage/%s" % (collection)
	if type(itemArray) == str:
		itemArrayJSON = itemArray
	else:
		itemArrayJSON = json.dumps(itemArray, ensure_ascii=False)

	logging.debug("payload:\n" + pprint.pformat(itemArrayJSON))
	
	return storage_http_op("POST", url, itemArrayJSON, ifUnmodifiedSince=ifUnmodifiedSince, withAuth=auth)


def delete_item(storageServerURL, auth, collection, id, ifUnmodifiedSince=None):
	"""Deletes the item identified by collection and id."""

	url = storageServerURL + "/storage/%s/%s" % (collection, urllib.quote(id))
	return storage_http_op("DELETE", url, ifUnmodifiedSince=ifUnmodifiedSince, withAuth=auth)

def delete_items(storageServerURL, auth, collection, idArray=None, params=None):
	"""Deletes the item identified by collection, idArray, and optional parameters."""

	# TODO: Replace params with named arguments.

	if params:
		if idArray:
			url = storageServerURL + "/storage/%s?ids=%s&%s" % (collection, urllib.quote(','.join(idArray)), params)
		else:
			url = storageServerURL + "/storage/%s?%s" % (collection, params)
	else:
		if idArray:
			url = storageServerURL + "/storage/%s?ids=%s" % (collection, urllib.quote(','.join(idArray)))
		else:
			url = storageServerURL + "/storage/%s" % (collection)
			
	return storage_http_op("DELETE", url, withAuth=auth)

def delete_items_older_than(storageServerURL, auth, collection, timestamp):
	"""Deletes all items in the given collection older than the provided timestamp."""

	url = storageServerURL + "/storage/%s?older=%s" % (collection, timestamp)
	return storage_http_op("DELETE", url, withAuth=auth)

def delete_all(storageServerURL, auth, confirm=True):
	"""Deletes all items in the given collection."""

	# The only reason you'd want confirm=False is for unit testing
	url = storageServerURL + "/storage"
	return storage_http_op("DELETE", url, asJSON=False, withConfirmation=confirm, withAuth=auth)

def get_collection_counts(storageServerURL, auth):
	"""Returns a map of all collection names and the number of objects in each."""

	url = storageServerURL + "/info/collection_counts"
	return storage_http_op("GET", url, withAuth=auth)

def get_collection_timestamps(storageServerURL, auth):
	"""Returns a map of the modified timestamp for each of the collections."""

	url = storageServerURL + "/info/collections"
	return storage_http_op("GET", url, withAuth=auth)

def get_collection_ids(storageServerURL, auth, collection, params=None, asJSON=True, outputFormat=None):
	"""Returns a list of IDs for objects in the specified collection."""

	# TODO replace params with named arguments
	if params:
		url = storageServerURL + "/storage/%s?%s" % (collection, params)
	else:
		url = storageServerURL + "/storage/%s" % (collection)
	return storage_http_op("GET", url, asJSON=asJSON, outputFormat=outputFormat, withAuth=auth)

def get_items(storageServerURL, auth, collection, asJSON=True):
	"""Returns all the items in the given collection."""
	logging.debug("get_items()")

	# The only reason to set withFalse=False is for unit testing
	url = storageServerURL + "/storage/%s?full=1" % (collection)
	return storage_http_op("GET", url, asJSON=asJSON, withAuth=auth)

def get_item(storageServerURL, auth, collection, id, asJSON=True):
	"""Returns the specified item."""

	# The only reason to set withFalse=False is for unit testing
	url = storageServerURL + "/storage/%s/%s?full=1" % (collection, id)
	return storage_http_op("GET", url, asJSON=asJSON, withAuth=auth)

def get_quota(storageServerURL, auth):
	"Returns an array of [<amount used>,<limit>].  Not implemented by Weave 1.0 production servers."

	url = storageServerURL + "/info/quota"
	return storage_http_op("GET", url, withAuth=auth)

def get_path(storageServerURL, auth, path):
	"Returns JSON object at given path"

	url = storageServerURL + "/storage/%s" % (path)
	return storage_http_op("GET", url, withAuth=auth)


############################################
# Weave Sync storage crypto implementation
############################################

from M2Crypto.EVP import Cipher

M2Crypto_Decrypt = 0
M2Crypto_Encrypt = 1

class WeaveKeypair(object):
	crypt_key = None
	hmac_key  = None

	def __init__(self, crypt_key, hmac_key):
		self.crypt_key = crypt_key
		self.hmac_key  = hmac_key


class WeaveCryptoContext(object):
	"""Encapsulates the cryptographic context for a user and their collections."""

	ctx          = None
	privateKey   = None
	privateHmac  = None
	bulkKeys     = None
	bulkKeyIVs   = None
	bulkKeyHmacs = None


	@staticmethod
	def get_instance(params):
		logging.debug("WeaveCrypto.getInstance()")

		storage_version = None
		if 'storage_version' in params:
			storage_version = params['storage_version']
		else:
			storage_version = "V5"

		#dynamically instansiate WeaveCryptoContext
		wc_name  = "WeaveCrypto" + storage_version
		wc_class = getattr(sys.modules[__name__], wc_name)

		#instansiate and initialise class
		wc = wc_class()
		wc.init_from_params(params)
		
		return wc


	def fetchPrivateKey(self):
		pass

	
	def fetchBulkKey(self, label):
		"""Given a bulk key label, pull the key down from the network,
		and decrypt it using my private key.  Then store the key
		into self storage for later decrypt operations."""
		
		logging.debug("fetchBulkKey()")

		# Do we have the key already?
		if label in self.bulkKeys:
			return

		logging.info("Fetching encrypted bulk key for %s" % label)

		itemPayload = self.ctx.get_keys()

		# Recursively call decrypt to extract key for label
		keyData = json.loads(self.decrypt(itemPayload))

		keyLabel = label
		if label not in keyData:
			keyLabel = 'default'

		if keyLabel not in keyData:
			raise WeaveException("No key found for label %s" % label)

		self.bulkKeys[label] = base64.decodestring(keyData[keyLabel][0])
		self.bulkKeyHmacs[label] = base64.decodestring(keyData[keyLabel][1])			

		logging.debug("Successfully decrypted bulk key for %s" % label)


	def decrypt_weave_basic_object(self, wbo, encryptionLabel=None):
		
		logging.debug("decrypt_weave_basic_object()")

		cleartext = self.decrypt(wbo['payload'], encryptionLabel)

		wboDecrypt = wbo;
		wboDecrypt['payload'] = cleartext;

		return wboDecrypt

	
	def decrypt(self, encryptedObject, encryptionLabel=None):
		"""Given an encrypted object, decrypt it and return the plaintext value.
		If necessary, will retrieve the private key and bulk encryption key
		from the storage context associated with self."""

		logging.debug("decrypt()")

		# Coerce JSON if necessary
		if type(encryptedObject) == str or type(encryptedObject) == unicode:
			encryptedObject = json.loads(encryptedObject)

		v = None
		
		# An encrypted object has three relevant fields
		ciphertext	= base64.decodestring(encryptedObject['ciphertext'])
		iv			= base64.decodestring(encryptedObject['IV'])
		cipher_hmac = encryptedObject['hmac'].encode('ascii')
		
		crypt_key	= None
		crypt_hmac	= None
			
		if encryptionLabel == None:
			logging.debug("Decrypting data record using sync key")

			# Go get the keying infromation if need it
			if self.privateKey == None:
				self.fetchPrivateKey()

			crypt_key  = self.privateKey
			crypt_hmac = self.privateHmac

		else:
			logging.debug("Decrypting data record using bulk key %s" % encryptionLabel)

			# Go get the keying infromation if need it
			if encryptionLabel not in self.bulkKeys:
				self.fetchBulkKey(encryptionLabel)

			crypt_key  = self.bulkKeys[encryptionLabel]
			crypt_hmac = self.bulkKeyHmacs[encryptionLabel]

		#logging.debug("payload: %s, crypt key:	 %s, crypt hmac: %s" % (encryptedObject, binascii.hexlify(crypt_key), binascii.hexlify(crypt_hmac)))
			
		# HMAC verification is done against base64 encoded ciphertext
		local_hmac = hmac.new(crypt_hmac, msg=encryptedObject['ciphertext'], digestmod=hashlib.sha256).digest()
		local_hmac = binascii.hexlify(local_hmac)
			
		if local_hmac != cipher_hmac:
			raise WeaveException("HMAC verification failed!")
				
		# In case you were wondering, this is the same as this operation at the openssl command line:
		# openssl enc -d -in data -aes-256-cbc -K `cat unwrapped_symkey.16` -iv `cat iv.16`

		# Do the decrypt
		cipher = Cipher(alg='aes_256_cbc', key=crypt_key, iv=iv, op=M2Crypto_Decrypt)
		v = cipher.update(ciphertext)
		v = v + cipher.final()
		del cipher
		logging.debug("Successfully decrypted v5 data record")
			
		return v


	def encrypt(self, plaintextData, encryptionLabel=None):
		"""Given a plaintext object, encrypt it and return the ciphertext value."""

		logging.debug("encrypt()")
		logging.debug("plaintext:\n" + pprint.pformat(plaintextData))
		
		crypt_key	= None
		hmac_key	= None
			
		if encryptionLabel == None:
			logging.debug("Encrypting data record using sync key")

			# Go get the keying infromation if need it
			if self.privateKey == None:
				self.fetchPrivateKey()
				
			crypt_key  = self.privateKey
			hmac_key   = self.privateHmac

		else:
			logging.debug("Encrypting data record using bulk key %s" % encryptionLabel)

			# Go get the keying infromation if need it
			if encryptionLabel not in self.bulkKeys:
				self.fetchBulkKey(encryptionLabel)
				
			crypt_key  = self.bulkKeys[encryptionLabel]
			hmac_key   = self.bulkKeyHmacs[encryptionLabel]


		encryptedData = None

		if isinstance(plaintextData, list):
				
			# Encrypt collection
			encryptedData = []
			for item in plaintextData:
				# Note recursive call
				encryptedData.append({u'id': unicode(item['id']), u'payload': json.dumps(self.encrypt(item['payload'], encryptionLabel), ensure_ascii=False)})

		else:

			# Encrypt item
			if type(plaintextData) != str and (plaintextData) != unicode:
				plaintextData = json.dumps(plaintextData, ensure_ascii=False)
				
			#logging.debug("payload: %s, crypt key:	 %s, crypt hmac: %s" % (plaintextData, binascii.hexlify(crypt_key), binascii.hexlify(hmac_key)))

			# Encrypt object
			iv			  = os.urandom(16)
			cipher		  = Cipher(alg='aes_256_cbc', key=crypt_key, iv=iv, op=M2Crypto_Encrypt)
			encryptedData = cipher.update(plaintextData) + cipher.final()				 
			del cipher
				
			#format for Weave storage, i.e. base64 unicode
			ciphertext = unicode(base64.b64encode(encryptedData))
			ivtext	   = unicode(base64.b64encode(iv))
			hmactext   = unicode(binascii.hexlify(hmac.new(hmac_key, msg=ciphertext, digestmod=hashlib.sha256).digest()))

			encryptedData = {u'ciphertext': ciphertext, u'IV': ivtext, u'hmac': hmactext}
			
		logging.debug("Successfully encrypted v5 data record")

		return encryptedData


class WeaveCryptoV5(WeaveCryptoContext):
	"""Encapsulates the cryptographic context for a user and their collections."""

	def init_from_params(self, params):
		self.init(
			params['storage_client'],
			params['keypair']
		)
		
	def init(self, storage_client, keypair):

		self.ctx = storage_client
		
		self.privateKey   = keypair.crypt_key
		self.privateHmac  = keypair.hmac_key
		
		self.bulkKeys     = {}
		self.bulkKeyIVs   = {}
		self.bulkKeyHmacs = {}


class WeaveCryptoV6(WeaveCryptoContext):
	"""Encapsulates the cryptographic context for a user and their collections."""

	def __init__(self):
		raise WeaveException("Not yet implemented")


########################################
# Weave Sync client implementation
########################################

class WeaveClient(object):
	"""Abstracts access to Weave Sync storage. Supports multiple storage API/crypto combinations"""

	ctx          = None
	crypto       = None
	
	@staticmethod
	def get_instance(params):
		logging.debug("WeaveClient.getInstance()")

		api_version = None
		if 'api_version' in params:
			api_version = params['api_version']
		else:
			api_version = "v1_1"

		#dynamically instansiate WeaveClientContext
		wc_name  = "WeaveClient" + api_version
		wc_class = getattr(sys.modules[__name__], wc_name)

		#instansiate and initialise class
		wc = wc_class()
		wc.init_from_params(params)
		
		return wc


	def get_api_version(self):
		return self.ctx.version


	def get_storage_version(self):
		return self.crypto.version


	def get(self, collection, id, decrypt=True):
		wbo = self.ctx.get(collection, id)

		if ( decrypt ):
			wbo = self.crypto.decrypt_weave_basic_object(wbo, collection)

		return wbo

		
	def get_collection_ids(collection, params=None):
		return self.ctx.get_collection_ids(collection, params=params)


	def get_collection(self, collection, decrypt=True):
		colWbo = self.ctx.get_collection(collection)

		if ( decrypt ):
			colWboDecrypt = []
			for wbo in colWbo:
				colWboDecrypt.append(self.crypto.decrypt_weave_basic_object(wbo, collection))
			
			colWbo = colWboDecrypt

		return colWbo


	def put(self, collection, id, item, encrypt=True):

		if encrypt:
			item = self.crypo.encrypt(item, collection)
		
		return self.ctx.put(collection, id, item)


	def put_collection(collection, itemArray, encrypt=True):

		if encrypt:
			colWboEncrypt = []
			for item in itemArray:
				colWboEncrypt.append(self.crypto.encrypt(item, collection))

			itemArray = colWboEncrypt
		
		return self.ctx.put_collection(collection, itemArray)


	def delete(collection, id):
		return self.ctx.delete(collection, id)


	def delete_collection(self, collection, idArray=None, params=None):
		return self.ctx.delete_collection(collection, idArray=idArray, params=params)


class WeaveClientV1_1(WeaveClient):
	"""Encapsulates the cryptographic context for a user and their collections."""
	
	def init_from_params(self, params):
		self.init(
			params['account_server'],
			params['username'],
			params['password'],
			params['synckey']
		)
		
	def init(self, account_server, username, password, synckey):

		# Instansiate account
		account = WeaveAccountLegacy()
		account.init(account_server, username, password)

		# Instansiate storage client
		self.ctx = WeaveStorageV1_1(account, username, password)

		# Get sync keypair
		sync_keypair = self.derive_sync_keypair(self.decode_synckey(synckey), username)

		# Check storage version
		meta = self.ctx.get_meta()
		storage_version = "V" + str(meta['storageVersion'])

		# Instansiate crypto client
		params = {
			'storage_version': storage_version,
			'storage_client': self.ctx,
			'keypair': sync_keypair,
		}
		
		self.crypto = WeaveCryptoContext.get_instance(params)


	def decode_synckey(self, synckey):
		"""Decode base32 encoded synckey
		NOTE: non-standard base32 encoding is used so encoding must first be normalised
		"""
		
		# Remove dash chars, convert to uppercase and translate 8 and 9 to L and O
		synckey_b32 = string.translate(str.upper(synckey), string.maketrans('89', 'LO'), '-')
		
		#logging.debug("normalised sync key: %s" % synckey_b32)
		
		# Pad base32 string to multiple of 8 chars (40 bits)
		if (len(synckey_b32) % 8) > 0:
			paddedLength = len(synckey_b32) + 8 - (len(synckey_b32) % 8)
			synckey_b32 = synckey_b32.ljust(paddedLength, '=')

		synckey_bin = base64.b32decode(synckey_b32)
		
		return synckey_bin


	def derive_sync_keypair(self, synckey, username):
		"""Derive the private keypair for the sync account"""
		
		logging.debug("derive_sync_keypair()")

		# Generate key pair using SHA-256 HMAC-based HKDF of sync key
		# See https://docs.services.mozilla.com/sync/storageformat5.html#the-sync-key
					
		keyInfo = 'Sync-AES_256_CBC-HMAC256' + username

		# For testing only
		#synckey = binascii.unhexlify("c71aa7cbd8b82a8ff6eda55c39479fd2")
		#keyInfo = 'Sync-AES_256_CBC-HMAC256' + "johndoe@example.com"
		
		#logging.debug("base32 key: %s decoded to %s" % (self.synckey, binascii.hexlify(syncKey)))
		
		crypt_key = hmac.new(synckey, msg=keyInfo + chr(0x01), digestmod=hashlib.sha256).digest()
		hmac_key  = hmac.new(synckey, msg=crypt_key + keyInfo + chr(0x02), digestmod=hashlib.sha256).digest()
		
		logging.info("Successfully generated sync key and hmac key")
		logging.debug("sync key: %s, crypt key: %s, hmac key: %s" % (binascii.hexlify(synckey), binascii.hexlify(crypt_key), binascii.hexlify(hmac_key)))

		return WeaveKeypair(crypt_key, hmac_key)


class WeaveClientV1_5(WeaveClient):
	"""Encapsulates the cryptographic context for a user and their collections."""
	
	def init_from_params(self, params):
	
		synckey = None
		if 'synckey' in params:
			synckey = params['synckey']
		
		self.init(
			params['account_server'],
			params['token_server'],			
			params['username'],
			params['password'],
			synckey=synckey
		)

	def init(self, account_server, token_server, username, password, synckey=None):
		logging.debug("WeaveClientV1_5.init()")

		# Instansiate account
		account = WeaveAccountFxA()
		account.init(account_server, token_server, username, password)

		# Instansiate storage client
		self.ctx = WeaveStorageV1_5(account)
		
		# Get sync keypair
		if not synckey == None:
			synckey = binascii.unhexlify(synckey)
		else:
			synckey = account.get_synckey()
		
		logging.debug("synckey: %s" % binascii.hexlify(synckey))

		sync_keypair = self.derive_sync_keypair(synckey)

		# Check storage version
		meta = self.ctx.get_meta()
		storage_version = "V" + str(meta['storageVersion'])

		# Instansiate crypto client
		params = {
			'storage_version': storage_version,
			'storage_client': self.ctx,
			'keypair': sync_keypair,
		}
		
		self.crypto = WeaveCryptoContext.get_instance(params)


	def derive_sync_keypair(self, synckey):
		logging.debug("derive_sync_keypair()")

		kdf = HKDF(
			algorithm=hashes.SHA256(),
			length=2*32,
			salt=b"",
			info=b"identity.mozilla.com/picl/v1/oldsync",
			backend=default_backend()
		)
		key = kdf.derive(synckey)

		crypt_key = key[:32]
		hmac_key  = key[32:]

		logging.info("Successfully generated sync key and hmac key")
		logging.debug("sync key: %s, crypt key: %s, hmac key: %s" % (binascii.hexlify(synckey), binascii.hexlify(crypt_key), binascii.hexlify(hmac_key)))

		return WeaveKeypair(crypt_key, hmac_key)

		
# Command-Line helper utilities

class TextFormatter(object):
	def format(self, obj):
		self.recursePrint(obj, 0)

	def recursePrint(self, obj, depth):
		pad = ''.join([' ' for i in xrange(depth)])

		if type(obj) == dict: # yuck, what's the duck-typing way to check for dictionary protocol?
			for key, value in obj.items():
				if type(value) == unicode or type(value) == str:
					print "%s%s: %s" % (pad, key, value)
				else:
					print "%s%s:" % (pad, key)
					self.recursePrint(value, depth+1)
		# If the object is iterable (and not a string, strings are a special case and don't have an __iter__)
		elif hasattr(obj,'__iter__'):
			for i in obj:
				if depth == 1: print "-----"
				self.recursePrint(i, depth)
		else:
			print "%s%s" % (pad, obj)


class XMLFormatter(object):
	def format(self, obj):
		pass

class JSONFormatter(object):
	def format(self, obj):
		print json.dumps(obj)


# Begin main: If you're running in library mode, none of this matters.

if __name__ == "__main__":

	import sys
	from optparse import OptionParser

	FORMATTERS = {"text": TextFormatter(), "xml": XMLFormatter(), "json": JSONFormatter() }

	# process arguments
	parser = OptionParser()
	parser.add_option("-s", "--account-server", help="account server url if you are not using defaults", dest="account_server")
	parser.add_option("-t", "--token-server", help="sync token server url if you are not using defaults", dest="token_server")

	parser.add_option("-u", "--user", help="username", dest="username")
	parser.add_option("-p", "--password", help="password (sent securely to server)", dest="password")
	parser.add_option("-k", "--synckey", help="synckey (used locally)", dest="synckey")
	parser.add_option("-K", "--credentialfile", help="get username, password, and synckey from this credential file (as name=value lines)", dest="credentialfile")
	parser.add_option("-c", "--collection", help="collection", dest="collection")
	parser.add_option("-i", "--id", help="object ID", dest="id")
	parser.add_option("-f", "--format", help="format (json|xml|text). Defaults to json", default="json", dest="format")
	parser.add_option("-v", "--api-version", help="weave sync storage api version (V1_1|V1_5). Defaults to V1_1", dest="api_version")
	parser.add_option("-l", "--log-level", help="set log level (critical|error|warn|info|debug). Defaults to info", dest="loglevel")
	parser.add_option("-m", "--modify", help="Update collection, or single item, with given value in JSON format. Requires -c and optionally -i", dest="modify")
	parser.add_option("", "--plaintext", help="plaintext collection, don't decrypt", action="store_true", dest="plaintext")
	parser.add_option("", "--test-mode", help="use test data", action="store_true", dest="testmode")


	(options, args) = parser.parse_args()

	if options.credentialfile:
		if options.username:
			print "The 'username' option must not be used when a credential file is provided."
			sys.exit(1)
		if options.password:
			print "The 'password' option must not be used when a credential file is provided."
			sys.exit(1)
		if options.synckey:
			print "The 'synckey' option must not be used when a credential file is provided."
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
					elif key == 'synckey':
						options.synckey = value.strip()
		except Exception, e:
			import traceback
			traceback.print_exc(e)
			print e
			sys.exit(1)

	if options.modify and not options.collection:
		print "The modify argument requires that the collection argument is also set. Use -h for help."
		sys.exit(1)

	formatter = FORMATTERS[options.format]

	if options.testmode:
		print "weaveaccount.TEST_MODE: " + str(WA_TEST_MODE)
		WA_TEST_MODE = True
		print "weaveaccount.TEST_MODE: " + str(WA_TEST_MODE)

	if options.loglevel:
		logging.basicConfig(level = str.upper(options.loglevel))
	else:
		logging.basicConfig(level = logging.ERROR)

	if options.plaintext:
		decrypt=False
	else:
		decrypt=True
	
	if options.api_version:
		api_version = options.api_version
	else:
		api_version = "V1_1"

	if options.synckey:
		synckey = options.synckey
	else:
		synckey = None

	if api_version == "V1_1":

		if options.account_server:
			account_server = options.account_server
		else:
			account_server="https://auth.services.mozilla.com"

		wc_params = {
			'api_version': "V1_1",
			'account_server': account_server,
			'username': options.username,
			'password': options.password,
			'synckey': synckey,
		}
		
	elif api_version == "V1_5":

		if options.account_server:
			account_server = options.account_server
		else:
			account_server="https://api.accounts.firefox.com"

		if options.token_server:
			token_server = options.token_server
		else:
			token_server="https://token.services.mozilla.com"

		wc_params = {
			'api_version': "V1_5",
			'account_server': account_server,
			'token_server': token_server,
			'username': options.username,
			'password': options.password,
		}
		if not synckey == None:
			wc_params['synckey'] = synckey
		
	else:
		raise WeaveException("API version '%s' not supported" % api_version)
		
	weaveClient = WeaveClient.get_instance(wc_params)

	# Now do what the user asked for

	if options.modify:
		if options.modify == '-':
			modifyData = sys.stdin.read()
		else:
			modifyData = options.modify
		
		logging.debug("modify data:\n" + modifyData)
		
		if options.id:
			# Single item
			logging.debug("payload:\n" + pprint.pformat(modifyData))
			result = weaveClient.put(options.collection, options.id, modifyData)
			logging.debug("result:\n" + pprint.pformat(result))

		else:
			# Collection
			logging.debug("payload:\n" + pprint.pformat(modifyData))
			result = weaveClient.put_collection(options.collection, modifyData)
			logging.debug("result:\n" + pprint.pformat(result))
			
	elif options.collection:
		if options.id:
			# Single item
			wbo = weaveClient.get(options.collection, options.id, decrypt=decrypt)
			logging.debug("item:\n" + pprint.pformat(wbo))
			if len(wbo['payload']) > 0:
				# Empty length payload is legal: indicates a deleted item
				itemObject = json.loads(wbo['payload'])
				formatter.format(itemObject)
				
		else:
			# Collection
			colWbo = weaveClient.get_collection(options.collection, decrypt=decrypt)
			logging.debug("collection:\n" + pprint.pformat(colWbo))
			for wbo in colWbo:
				if len(wbo['payload']) > 0:
					itemObject = json.loads(wbo['payload'])
					formatter.format(itemObject)
			
	else:
		print "No command provided: use -h for help"
