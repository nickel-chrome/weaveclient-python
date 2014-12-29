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
from hawk.util import parse_normalized_url

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from weaveinclude import WeaveException
from weaveaccount import WeaveAccountV5Context, WeaveAccountV6Context, TEST_MODE as WA_TEST_MODE

class WeaveAuthBasicContext(object):

	def __init__(self, username, password):
		self.header_key = "Authorization"
		self.header_val = "Basic %s" % base64.encodestring('%s:%s' % (username, password))[:-1]

	def get_auth_header(self, method, url, data):
		return self.header_key, self.header_val


class WeaveAuthHawkContext(object):
	
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


class WeaveStorageContext(object):
	"""An object that encapsulates a server, userID, and password, to simplify
	storage calls for the client."""

	storage_version = None
	api_version     = None
	
	storageUrl      = None
	storageAuth     = None
	userID          = None

	def http_get(self, url):
		return storage_http_op("GET", self.userID, self.storageAuth, url)

	def put(self, collection, item, urlID=None, ifUnmodifiedSince=None):
		return add_or_modify_item(self.storageUrl, self.userID, self.storageAuth, collection, item, urlID=urlID, ifUnmodifiedSince=ifUnmodifiedSince)

	def put_collection(self, collection, itemArray, ifUnmodifiedSince=None):
		return add_or_modify_items(self.storageUrl, self.userID, self.storageAuth, collection, itemArray, ifUnmodifiedSince=ifUnmodifiedSince)

	def delete(self, collection, id, ifUnmodifiedSince=None):
		return delete_item(self.storageUrl, self.userID, self.storageAuth, collection, id, ifUnmodifiedSince=ifUnmodifiedSince)

	def delete_collection(self, collection, idArray=None, params=None):
		return delete_items(self.storageUrl, self.userID, self.storageAuth, collection, idArray=idArray, params=params)

	def delete_items_older_than(self, collection, timestamp):
		return delete_items_older_than(self.storageUrl, self.userID, self.storageAuth, collection, timestamp)

	def delete_all(self):
		return delete_all(self.storageUrl, self.userID, self.storageAuth)

	def get_collection_counts(self):
		return get_collection_counts(self.storageUrl, self.userID, self.storageAuth)

	def get_collection_timestamps(self):
		return get_collection_timestamps(self.storageUrl, self.userID, self.storageAuth)

	def get_collection_ids(self, collection, params=None, asJSON=True, outputFormat=None):
		return get_collection_ids(self.storageUrl, self.userID, self.storageAuth, collection, params=params, asJSON=asJSON, outputFormat=outputFormat)

	def get(self, collection, id, asJSON=True):
		return get_item(self.storageUrl, self.userID, self.storageAuth, collection, id, asJSON=asJSON)

	def get_collection(self, collection, asJSON=True):
		return get_items(self.storageUrl, self.userID, self.storageAuth, collection, asJSON=asJSON)

	def get_quota(self):
		return get_quota(self.storageUrl, self.userID, self.storageAuth)

	def get_meta(self):
		"""Returns an array of meta information. Storage version 5 only"""
		item = get_path(self.storageUrl, self.userID, self.storageAuth, 'meta/global')
		return json.loads(item['payload'])

	def get_keys(self):
		"""Returns storage keys. Storage version 5 only"""
		item = get_path(self.storageUrl, self.userID, self.storageAuth, 'crypto/keys')
		return json.loads(item['payload'])


class WeaveStorageV5Context(WeaveStorageContext):
	"""An object that encapsulates a server, userID, and password, to simplify
	storage calls for the client."""

	storage_version = 5
	api_version     = "1.1"

	def __init__(self, server, username, password):
		
		account = WeaveAccountV5Context()
		account.init(server, username, password)

		self.storageUrl  = account.get_storage_url() + "/%s/%s" % (self.storage_version, username)
		self.storageAuth = WeaveAuthBasicContext(username, password)
		self.userID      = username

		# Check storage version
		meta = self.get_meta()
		if not int(meta['storageVersion']) == self.storage_version:
			raise WeaveException("Storage version %s not supported" % meta['storageVersion'])


class WeaveStorageV6Context(WeaveStorageContext):
	"""An object that encapsulates a server, userID, and password, to simplify
	storage calls for the client."""

	#storage_version = 6
	storage_version = 5
	api_version     = "1.5"
	
	def __init__(self, accountServer, tokenServer, username, password):
		logging.debug("WeaveStorageV6Context()")
		
		self.account = WeaveAccountV6Context()
		self.account.init(accountServer, tokenServer, username, password)
		token = self.account.get_auth_token()

		logging.debug("auth token\n:" + pprint.pformat(token))
		
		self.storageUrl  = token['api_endpoint']

		#IMPORTANT - ignore urlsafe base64 encoding of id and key. use id as-is and encode key as utf8
		hawk_id  = token['id']
		hawk_key = token['key'].encode('utf8')

		self.storageAuth = WeaveAuthHawkContext(hawk_id, hawk_key)
		self.userID      = username

		# Check storage version
		meta = self.get_meta()
		if not int(meta['storageVersion']) == self.storage_version:
			raise WeaveException("Storage version %s not supported" % meta['storageVersion'])


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


def add_or_modify_item(storageServerURL, userID, auth, collection, item, urlID=None, ifUnmodifiedSince=None):
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

def add_or_modify_items(storageServerURL, userID, auth, collection, itemArray, ifUnmodifiedSince=None):
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


def delete_item(storageServerURL, userID, auth, collection, id, ifUnmodifiedSince=None):
	"""Deletes the item identified by collection and id."""

	url = storageServerURL + "/storage/%s/%s" % (collection, urllib.quote(id))
	return storage_http_op("DELETE", url, ifUnmodifiedSince=ifUnmodifiedSince, withAuth=auth)

def delete_items(storageServerURL, userID, auth, collection, idArray=None, params=None):
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

def delete_items_older_than(storageServerURL, userID, auth, collection, timestamp):
	"""Deletes all items in the given collection older than the provided timestamp."""

	url = storageServerURL + "/storage/%s?older=%s" % (collection, timestamp)
	return storage_http_op("DELETE", url, withAuth=auth)

def delete_all(storageServerURL, userID, auth, confirm=True):
	"""Deletes all items in the given collection."""

	# The only reason you'd want confirm=False is for unit testing
	url = storageServerURL + "/storage"
	return storage_http_op("DELETE", url, asJSON=False, withConfirmation=confirm, withAuth=auth)

def get_collection_counts(storageServerURL, userID, auth):
	"""Returns a map of all collection names and the number of objects in each."""

	url = storageServerURL + "/info/collection_counts"
	return storage_http_op("GET", url, withAuth=auth)

def get_collection_timestamps(storageServerURL, userID, auth):
	"""Returns a map of the modified timestamp for each of the collections."""

	url = storageServerURL + "/info/collections"
	return storage_http_op("GET", url, withAuth=auth)

def get_collection_ids(storageServerURL, userID, auth, collection, params=None, asJSON=True, outputFormat=None):
	"""Returns a list of IDs for objects in the specified collection."""

	# TODO replace params with named arguments
	if params:
		url = storageServerURL + "/storage/%s?%s" % (collection, params)
	else:
		url = storageServerURL + "/storage/%s" % (collection)
	return storage_http_op("GET", url, asJSON=asJSON, outputFormat=outputFormat, withAuth=auth)

def get_items(storageServerURL, userID, auth, collection, asJSON=True):
	"""Returns all the items in the given collection."""
	logging.debug("get_items()")

	# The only reason to set withFalse=False is for unit testing
	url = storageServerURL + "/storage/%s?full=1" % (collection)
	return storage_http_op("GET", url, asJSON=asJSON, withAuth=auth)

def get_item(storageServerURL, userID, auth, collection, id, asJSON=True):
	"""Returns the specified item."""

	# The only reason to set withFalse=False is for unit testing
	url = storageServerURL + "/storage/%s/%s?full=1" % (collection, id)
	return storage_http_op("GET", url, asJSON=asJSON, withAuth=auth)

def get_quota(storageServerURL, userID, auth):
	"Returns an array of [<amount used>,<limit>].  Not implemented by Weave 1.0 production servers."

	url = storageServerURL + "/info/quota"
	return storage_http_op("GET", url, withAuth=auth)

def get_path(storageServerURL, userID, auth, path):
	"Returns JSON object at given path"

	url = storageServerURL + "/storage/%s" % (path)
	return storage_http_op("GET", url, withAuth=auth)


# Crypto implementation:
from PBKDF2 import PBKDF2
from M2Crypto.EVP import Cipher, RSA, load_key_string
import M2Crypto.m2

M2Crypto_Decrypt = 0
M2Crypto_Encrypt = 1


class WeaveClient(object):
	"""Encapsulates the cryptographic context for a user and their collections."""

	ctx          = None
	passphrase   = None
	privateKey   = None
	privateHmac  = None
	bulkKeys     = None
	bulkKeyIVs   = None
	bulkKeyHmacs = None


	def fetchPrivateKey(self):
		"""Fetch the private key for the user and storage context
		provided to this object, and decrypt the private key
		by using my passphrase.	 Store the private key in internal
		storage for later use."""
		logging.debug("fetchPrivateKey()")

		if self.ctx.storage_version == 5:

			# Generate key pair using SHA-256 HMAC-based HKDF of sync key
			# See https://docs.services.mozilla.com/sync/storageformat5.html#the-sync-key
 
			# Remove dash chars, convert to uppercase and translate 8 and 9 to L and O
			syncKeyB32 = string.translate(str.upper(self.passphrase), string.maketrans('89', 'LO'), '-')

			#logging.debug("normalised sync key: %s" % syncKeyB32)
	
			# Pad base32 string to multiple of 8 chars (40 bits)
			if (len(syncKeyB32) % 8) > 0:
				paddedLength = len(syncKeyB32) + 8 - (len(syncKeyB32) % 8)
				syncKeyB32 = syncKeyB32.ljust(paddedLength, '=')

			syncKey = base64.b32decode(syncKeyB32)
			
			keyInfo = 'Sync-AES_256_CBC-HMAC256' + self.ctx.userID

			# For testing only
			#syncKey = binascii.unhexlify("c71aa7cbd8b82a8ff6eda55c39479fd2")
			#keyInfo = 'Sync-AES_256_CBC-HMAC256' + "johndoe@example.com"

			#logging.debug("base32 key: %s decoded to %s" % (self.passphrase, binascii.hexlify(syncKey)))

			self.privateKey	 = hmac.new(syncKey, msg=keyInfo + chr(0x01), digestmod=hashlib.sha256).digest()
			self.privateHmac = hmac.new(syncKey, msg=self.privateKey + keyInfo + chr(0x02), digestmod=hashlib.sha256).digest()

			logging.info("Successfully generated sync key and hmac key")
			logging.debug("sync key: %s, crypt key: %s, crypt hmac: %s" % (binascii.hexlify(syncKey), binascii.hexlify(self.privateKey), binascii.hexlify(self.privateHmac)))

			
		elif self.ctx.storage_version == 3:

			# Retrieve encrypted private key from the server
			logging.info("Fetching encrypted private key from server")
			privKeyObj = self.ctx.get_item("keys", "privkey")
			payload = json.loads(privKeyObj['payload'])
			self.privKeySalt = base64.decodestring(payload['salt'])
			self.privKeyIV = base64.decodestring(payload['iv'])
			self.pubKeyURI = payload['publicKeyUri']
			
			data64 = payload['keyData']
			encryptedKey = base64.decodestring(data64)
			
			# Now decrypt it by generating a key with the passphrase
			# and performing an AES-256-CBC decrypt.
			logging.info("Decrypting encrypted private key")

			passKey = PBKDF2(self.passphrase, self.privKeySalt, iterations=4096).read(32)
			cipher = Cipher(alg='aes_256_cbc', key=passKey, iv=self.privKeyIV, op=M2Crypto_Decrypt)
			cipher.set_padding(padding=1)
			v = cipher.update(encryptedKey)
			v = v + cipher.final()
			del cipher
			decryptedKey = v


			# Result is an NSS-wrapped key.
			# We have to do some manual ASN.1 parsing here, which is unfortunate.
			
			# 1. Make sure offset 22 is an OCTET tag; if this is not right, the decrypt
			# has gone off the rails.
			if ord(decryptedKey[22]) != 4:
				logging.debug("Binary layout of decrypted private key is incorrect; probably the passphrase was incorrect.")
				raise ValueError("Unable to decrypt key: wrong passphrase?")

			# 2. Get the length of the raw key, by interpreting the length bytes
			offset = 23
			rawKeyLength = ord(decryptedKey[offset])
			det = rawKeyLength & 0x80
			if det == 0: # 1-byte length
				offset += 1
				rawKeyLength = rawKeyLength & 0x7f
			else: # multi-byte length
				bytes = rawKeyLength & 0x7f
				offset += 1

				rawKeyLength = 0
				while bytes > 0:
					rawKeyLength *= 256
					rawKeyLength += ord(decryptedKey[offset])
					offset += 1
					bytes -= 1

			# 3. Sanity check
			if offset + rawKeyLength > len(decryptedKey):
				rawKeyLength = len(decryptedKey) - offset

			# 4. Extract actual key
			privateKey = decryptedKey[offset:offset+rawKeyLength]

			# And we're done.
			self.privateKey = privateKey
			logging.debug("Successfully decrypted private key")

		else:
			raise WeaveException("Storage version %s not supported" % self.ctx.storage_version)


	def fetchBulkKey(self, label):
		"""Given a bulk key label, pull the key down from the network,
		and decrypt it using my private key.  Then store the key
		into self storage for later decrypt operations."""
		logging.debug("fetchBulkKey()")

		# Do we have the key already?
		if label in self.bulkKeys:
			return

		if self.ctx.storage_version == 5:

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

		elif self.ctx.storage_version == 3:

			logging.info("Fetching encrypted bulk key from %s" % label)

			# Note that we do not currently support any authentication model for bulk key
			# retrieval other than the usual weave username-password pair.	To support
			# distributed key models for the more advanced sharing scenarios, we will need
			# to revisit that.
			keyData = self.ctx.http_get(label)
			keyPayload = json.loads(keyData['payload'])
			bulkIV = base64.decodestring(keyPayload['bulkIV'])

			keyRing = keyPayload['keyring']

			# In a future world where we have sharing, the keys of the keyring dictionary will
			# define public key domains for the symmetric bulk keys stored on the ring.
			# Right now, the first item is always the pubkey of a user, and we just grab the first value.

			# We should really make sure that the key we have here matches the private key
			# we're using to unwrap, or none of this makes sense.

			# Now, using the user's private key, we will unwrap the symmetric key.
			encryptedBulkKey = base64.decodestring(keyRing.items()[0][1])

			# This is analogous to this openssl command-line invocation:
			# openssl rsautl -decrypt -keyform DER -inkey privkey.der -in wrapped_symkey.dat -out unwrapped_symkey.dat
			#
			# ... except that M2Crypto doesn't have an API for DER importing,
			# so we have to PEM-encode the key (with base64 and header/footer blocks).
			# So what we're actually doing is:
			#
			# openssl rsautl -decrypt -keyform PEM -inkey privkey.pem -in wrapped_symkey.dat -out unwrapped_symkey.dat

			logging.debug("Decrypting encrypted bulk key %s" % label)

			pemEncoded = "-----BEGIN RSA PRIVATE KEY-----\n"
			pemEncoded += base64.encodestring(self.privateKey)
			pemEncoded += "-----END RSA PRIVATE KEY-----\n"

			# Create an EVP, extract the RSA key from it, and do the decrypt
			evp = load_key_string(pemEncoded)
			rsa = M2Crypto.m2.pkey_get1_rsa(evp.pkey)
			rsaObj = RSA.RSA(rsa)
			unwrappedSymKey = rsaObj.private_decrypt(encryptedBulkKey, RSA.pkcs1_padding)

			# And save it for later use
			self.bulkKeys[label] = unwrappedSymKey
			self.bulkKeyIVs[label] = bulkIV
			logging.debug("Successfully decrypted bulk key from %s" % label)

		return

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
		
		if self.ctx.storage_version == 5:

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
			
		elif self.ctx.storage_version == 3:
			
			# An encrypted object has two relevant fields
			encryptionLabel = encryptedObject['encryption']
			ciphertext = base64.decodestring(encryptedObject['ciphertext'])

			# Go get the keying infromation if need it
			if self.privateKey == None:
				self.fetchPrivateKey()
			if not encryptionLabel in self.bulkKeys:
				self.fetchBulkKey(encryptionLabel)

			# In case you were wondering, this is the same as this operation at the openssl command line:
			# openssl enc -d -in data -aes-256-cbc -K `cat unwrapped_symkey.16` -iv `cat iv.16`

			# Do the decrypt
			logging.debug("Decrypting data record using bulk key %s" % encryptionLabel)
			cipher = Cipher(alg='aes_256_cbc', key=self.bulkKeys[encryptionLabel], iv=self.bulkKeyIVs[encryptionLabel], op=M2Crypto_Decrypt)
			v = cipher.update(ciphertext)
			v = v + cipher.final()
			del cipher
			logging.debug("Successfully decrypted v3 data record")

		else:
			raise WeaveException("Storage version %s not supported" % self.ctx.storage_version)

		
		return v


	def encrypt(self, plaintextData, encryptionLabel=None):
		"""Given a plaintext object, encrypt it and return the ciphertext value."""

		logging.debug("encrypt()")
		logging.debug("plaintext:\n" + pprint.pformat(plaintextData))
		
		if self.ctx.storage_version == 5:

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

		else:
			raise WeaveException("Encryption not supported for storage version %s" % self.ctx.storage_version)


	def get(self, collection, id, decrypt=True):
		wbo = self.ctx.get(collection, id)

		if ( decrypt ):
			wbo = self.decrypt_weave_basic_object(wbo, collection)

		return wbo

		
	def get_collection_ids(collection, params=None):
		return self.ctx.get_collection_ids(collection, params=params)


	def get_collection(self, collection, decrypt=True):
		colWbo = self.ctx.get_collection(collection)

		colWboDecrypt = []
		if ( decrypt ):
			for wbo in colWbo:
				colWboDecrypt.append(self.decrypt_weave_basic_object(wbo, collection))
			
			colWbo = colWboDecrypt

		return colWbo


	def put(self, collection, id, item, encrypt=True):
		return self.ctx.put(collection, id, item)

	def put_collection(collection, itemArray):
		return self.ctx.put_collection(collection, itemArray)

	def delete(collection, id):
		return self.ctx.delete(collection, id)

	def delete_collection(self, collection, idArray=None, params=None):
		return self.ctx.delete_collection(collection, idArray=idArray, params=params)

				
class WeaveClientV5(WeaveClient):
	"""Encapsulates the cryptographic context for a user and their collections."""

	def __init__(self, rootServer, userID, password, passphrase):
		self.ctx          = WeaveStorageV5Context(rootServer, userID, password)
		self.passphrase   = passphrase
		self.privateKey   = None
		self.privateHmac  = None
		self.bulkKeys     = {}
		self.bulkKeyIVs   = {}
		self.bulkKeyHmacs = {}


class WeaveClientV6(WeaveClient):
	"""Encapsulates the cryptographic context for a user and their collections."""

	def __init__(self, account_server, token_server, username, password, synckey=None):
		logging.debug("WeaveClientV6()")
		
		self.ctx          = WeaveStorageV6Context(account_server, token_server, username, password)
		self.passphrase   = synckey
		self.privateKey   = None
		self.privateHmac  = None
		self.bulkKeys     = {}
		self.bulkKeyIVs   = {}
		self.bulkKeyHmacs = {}

		if self.passphrase == None:
			self.passphrase = self.ctx.account.synckey

		logging.debug("synckey: %s" % self.passphrase)
			
	def fetchPrivateKey(self):
		logging.debug("fetchPrivateKey()")

		kdf = HKDF(
			algorithm=hashes.SHA256(),
			length=2*32,
			salt=b"",
			info=b"identity.mozilla.com/picl/v1/oldsync",
			backend=default_backend()
		)
		key = kdf.derive(binascii.unhexlify(self.passphrase))

		self.privateKey  = key[:32]
		self.privateHmac = key[32:]

		logging.info("Successfully generated sync key and hmac key")
		logging.debug("sync key: %s, crypt key: %s, crypt hmac: %s" % (self.passphrase, binascii.hexlify(self.privateKey), binascii.hexlify(self.privateHmac)))


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
	parser.add_option("-k", "--passphrase", help="synckey (used locally)", dest="synckey")
	parser.add_option("-K", "--credentialfile", help="get username, password, and synckey from this credential file (as name=value lines)", dest="credentialfile")
	parser.add_option("-c", "--collection", help="collection", dest="collection")
	parser.add_option("-i", "--id", help="object ID", dest="id")
	parser.add_option("-f", "--format", help="format (default is text; options are text, json, xml)", default="text", dest="format")
	parser.add_option("-v", "--storage-version", help="weave client version (5|6). Defaults to v5", dest="storage_version")
	parser.add_option("-l", "--log-level", help="set log level (critical|error|warn|info|debug)", dest="loglevel")
	parser.add_option("-m", "--modify", help="Update collection, or single item, with given value in JSON format. Requires -c and optionally -i", dest="modify")
	parser.add_option("", "--plaintext", help="Plaintext collection, don't decrypt", action="store_true", dest="plaintext")
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
		# print "weaveaccount.TEST_MODE: " + str(wa_get_test_mode())
		# wa_set_test_mode(True)		
		# print "weaveaccount.TEST_MODE: " + str(wa_get_test_mode())
		
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
	
	if options.storage_version:
		storage_version = int(options.storage_version)
	else:
		storage_version = 5

	if options.synckey:
		synckey = options.synckey
	else:
		synckey = None

	if storage_version == 6:

		if options.account_server:
			account_server = options.account_server
		else:
			account_server="https://api.accounts.firefox.com"

		if options.token_server:
			token_server = options.token_server
		else:
			token_server="https://token.services.mozilla.com"

		weaveClient = WeaveClientV6(account_server, token_server, options.username, options.password, synckey=synckey)
	
	elif storage_version == 5:

		if options.account_server:
			account_server = options.account_server
		else:
			account_server="https://auth.services.mozilla.com"
		
		weaveClient = WeaveClientV5(account_server, options.username, options.password, synckey)
	else:
		raise WeaveException("Storage version '%s' not supported" % storage_version)
		

	#DEBUG only
	#sys.exit(0)
	
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
