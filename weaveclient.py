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

class WeaveException(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repr(self.value)


import weaveaccount

class WeaveStorageContext(object):
	"""An object that encapsulates a server, userID, and password, to simplify
	storage calls for the client."""

	def __init__(self, rootServer, userID, password):
		self.url = weaveaccount.WeaveRegistrationContext.get_storage_url(rootServer, userID, password)
		if self.url[len(self.url)-1] == '/': self.url = self.url[:len(self.url)-1]
		self.userID = userID
		self.password = password

		# Get storage version
		meta = self.get_meta()
		self.version = int(meta['storageVersion'])
		if not (self.version == 3 or self.version == 5):
			raise WeaveException("Storage version %s not supported" % self.version)
			
		logging.info("Created WeaveStorageContext (v%s) for %s at %s " % (self.version, self.userID, self.url))

	def http_get(self, url):
		return storage_http_op("GET", self.userID, self.password, url)

	def put(self, collection, item, urlID=None, ifUnmodifiedSince=None):
		return add_or_modify_item(self.url, self.userID, self.password, collection, item, urlID=urlID, ifUnmodifiedSince=ifUnmodifiedSince)

	def put_collection(self, collection, itemArray, ifUnmodifiedSince=None):
		return add_or_modify_items(self.url, self.userID, self.password, collection, itemArray, ifUnmodifiedSince=ifUnmodifiedSince)

	def delete(self, collection, id, ifUnmodifiedSince=None):
		return delete_item(self.url, self.userID, self.password, collection, id, ifUnmodifiedSince=ifUnmodifiedSince)

	def delete_collection(self, collection, idArray=None, params=None):
		return delete_items(self.url, self.userID, self.password, collection, idArray=idArray, params=params)

	def delete_items_older_than(self, collection, timestamp):
		return delete_items_older_than(self.url, self.userID, self.password, collection, timestamp)

	def delete_all(self):
		return delete_all(self.url, self.userID, self.password)

	def get_collection_counts(self):
		return get_collection_counts(self.url, self.userID, self.password)

	def get_collection_timestamps(self):
		return get_collection_timestamps(self.url, self.userID, self.password)

	def get_collection_ids(self, collection, params=None, asJSON=True, outputFormat=None):
		return get_collection_ids(self.url, self.userID, self.password, collection, params=params, asJSON=asJSON, outputFormat=outputFormat)

	def get(self, collection, id, asJSON=True):
		return get_item(self.url, self.userID, self.password, collection, id, asJSON=asJSON, withAuth=True)

	def get_collection(self, collection, asJSON=True):
		return get_items(self.url, self.userID, self.password, collection, asJSON=asJSON, withAuth=True)

	def get_quota(self):
		return get_quota(self.url, self.userID, self.password)

	def get_meta(self):
		"""Returns an array of meta information. Storage version 5 only"""
		item = get_path(self.url, self.userID, self.password, 'meta/global')
		return json.loads(item['payload'])

	def get_keys(self):
		"""Returns storage keys. Storage version 5 only"""
		item = get_path(self.url, self.userID, self.password, 'crypto/keys')
		return json.loads(item['payload'])


def storage_http_op(method, userID, password, url, payload=None, asJSON=True, ifUnmodifiedSince=None, withConfirmation=None, withAuth=True, outputFormat=None):
	"""Generic HTTP helper function.  Sets headers and performs I/O, optionally
	performing JSON parsing on the result."""

	req = urllib2.Request(url, data=payload)
	if withAuth:
		base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
		req.add_header("Authorization", "Basic %s" % base64string)
	if ifUnmodifiedSince:
		req.add_header("X-If-Unmodified-Since", "%s" % ifUnmodifiedSince)
	if withConfirmation:
		req.add_header("X-Confirm-Delete", "true")
	if outputFormat:
		req.add_header("Accept", outputFormat)

	req.get_method = lambda: method

	try:
		logging.info("Making %s request to %s%s" % (method, url, " with auth %s" % base64string if withAuth else ""))
		f = opener.open(req)
		result = f.read()
		if asJSON:
			return json.loads(result)
		else:
			return result
	except urllib2.URLError, e:
		msg = ""
		try:
			msg = e.read()
		except:
			pass
		# TODO process error code
		logging.debug("Communication error: %s, %s" % (e, msg))
		raise WeaveException("Unable to communicate with Weave server: %s" % e)


def add_or_modify_item(storageServerURL, userID, password, collection, item, urlID=None, ifUnmodifiedSince=None):
	'''Adds the WBO defined in 'item' to 'collection'.	If the WBO does
	not contain a payload, will update the provided metadata fields on an
	already-defined object.

	Returns the timestamp of the modification.'''

	logging.debug("add_or_modify_item()")

	if urlID:
		url = storageServerURL + "/1.0/%s/storage/%s/%s" % (userID, collection, urllib.quote(urlID))
	else:
		url = storageServerURL + "/1.0/%s/storage/%s" % (userID, collection)
	if type(item) == str:
		itemJSON = item
	else:
		itemJSON = json.dumps(item, ensure_ascii=False)

	logging.debug("payload:\n" + pprint.pformat(itemJSON))
	
	return storage_http_op("PUT", userID, password, url, itemJSON, asJSON=False, ifUnmodifiedSince=ifUnmodifiedSince)

def add_or_modify_items(storageServerURL, userID, password, collection, itemArray, ifUnmodifiedSince=None):
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
	
	url = storageServerURL + "/1.0/%s/storage/%s" % (userID, collection)
	if type(itemArray) == str:
		itemArrayJSON = itemArray
	else:
		itemArrayJSON = json.dumps(itemArray, ensure_ascii=False)

	logging.debug("payload:\n" + pprint.pformat(itemArrayJSON))
	
	return storage_http_op("POST", userID, password, url, itemArrayJSON, ifUnmodifiedSince=ifUnmodifiedSince)


def delete_item(storageServerURL, userID, password, collection, id, ifUnmodifiedSince=None):
	"""Deletes the item identified by collection and id."""

	url = storageServerURL + "/1.0/%s/storage/%s/%s" % (userID, collection, urllib.quote(id))
	return storage_http_op("DELETE", userID, password, url, ifUnmodifiedSince=ifUnmodifiedSince)

def delete_items(storageServerURL, userID, password, collection, idArray=None, params=None):
	"""Deletes the item identified by collection, idArray, and optional parameters."""
	# TODO: Replace params with named arguments.

	if params:
		if idArray:
			url = storageServerURL + "/1.0/%s/storage/%s?ids=%s&%s" % (userID, collection, urllib.quote(','.join(idArray)), params)
		else:
			url = storageServerURL + "/1.0/%s/storage/%s?%s" % (userID, collection, params)
	else:
		if idArray:
			url = storageServerURL + "/1.0/%s/storage/%s?ids=%s" % (userID, collection, urllib.quote(','.join(idArray)))
		else:
			url = storageServerURL + "/1.0/%s/storage/%s" % (userID, collection)
	return storage_http_op("DELETE", userID, password, url)

def delete_items_older_than(storageServerURL, userID, password, collection, timestamp):
	"""Deletes all items in the given collection older than the provided timestamp."""
	url = storageServerURL + "/1.0/%s/storage/%s?older=%s" % (userID, collection, timestamp)
	return storage_http_op("DELETE", userID, password, url)

def delete_all(storageServerURL, userID, password, confirm=True):
	"""Deletes all items in the given collection."""
	# The only reason you'd want confirm=False is for unit testing
	url = storageServerURL + "/1.0/%s/storage" % (userID)
	return storage_http_op("DELETE", userID, password, url, asJSON=False, withConfirmation=confirm)

def get_collection_counts(storageServerURL, userID, password):
	"""Returns a map of all collection names and the number of objects in each."""
	url = storageServerURL + "/1.0/%s/info/collection_counts" % (userID)
	return storage_http_op("GET", userID, password, url)

def get_collection_timestamps(storageServerURL, userID, password):
	"""Returns a map of the modified timestamp for each of the collections."""
	url = storageServerURL + "/1.0/%s/info/collections" % (userID)
	return storage_http_op("GET", userID, password, url)

def get_collection_ids(storageServerURL, userID, password, collection, params=None, asJSON=True, outputFormat=None):
	"""Returns a list of IDs for objects in the specified collection."""
	# TODO replace params with named arguments
	if params:
		url = storageServerURL + "/1.0/%s/storage/%s?%s" % (userID, collection, params)
	else:
		url = storageServerURL + "/1.0/%s/storage/%s" % (userID, collection)
	return storage_http_op("GET", userID, password, url, asJSON=asJSON, outputFormat=outputFormat)

def get_items(storageServerURL, userID, password, collection, asJSON=True, withAuth=True):
	"""Returns all the items in the given collection."""
	
	logging.debug("get_items()")

	# The only reason to set withFalse=False is for unit testing
	url = storageServerURL + "/1.0/%s/storage/%s?full=1" % (userID, collection)
	return storage_http_op("GET", userID, password, url, asJSON=asJSON, withAuth=withAuth)

def get_item(storageServerURL, userID, password, collection, id, asJSON=True, withAuth=True):
	"""Returns the specified item."""
	# The only reason to set withFalse=False is for unit testing
	url = storageServerURL + "/1.0/%s/storage/%s/%s?full=1" % (userID, collection, id)
	return storage_http_op("GET", userID, password, url, asJSON=asJSON, withAuth=withAuth)

def get_quota(storageServerURL, userID, password):
	"Returns an array of [<amount used>,<limit>].  Not implemented by Weave 1.0 production servers."
	url = storageServerURL + "/1.0/%s/info/quota" % (userID)
	return storage_http_op("GET", userID, password, url)

def get_path(storageServerURL, userID, password, path):
	"Returns JSON object at given path"	   
	url = storageServerURL + "/1.0/%s/storage/%s" % (userID, path)
	return storage_http_op("GET", userID, password, url)


	
# Crypto implementation:
from PBKDF2 import PBKDF2
from M2Crypto.EVP import Cipher, RSA, load_key_string
import M2Crypto.m2

M2Crypto_Decrypt = 0
M2Crypto_Encrypt = 1


class WeaveClient(object):
	"""Encapsulates the cryptographic context for a user and their collections."""

	def __init__(self, rootServer, userID, password, passphrase):
		self.ctx = WeaveStorageContext(rootServer, userID, password)
		self.passphrase = passphrase
		self.privateKey = None
		self.privateHmac = None
		self.bulkKeys = {}
		self.bulkKeyIVs = {}
		self.bulkKeyHmacs = {}

	def fetchPrivateKey(self):
		"""Fetch the private key for the user and storage context
		provided to this object, and decrypt the private key
		by using my passphrase.	 Store the private key in internal
		storage for later use."""
		logging.debug("fetchPrivateKey()")

		if self.ctx.version == 5:

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

			
		elif self.ctx.version == 3:

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
			raise WeaveException("Storage version %s not supported" % self.ctx.version)


	def fetchBulkKey(self, label):
		"""Given a bulk key label, pull the key down from the network,
		and decrypt it using my private key.  Then store the key
		into self storage for later decrypt operations."""
		logging.debug("fetchBulkKey()")

		# Do we have the key already?
		if label in self.bulkKeys:
			return

		if self.ctx.version == 5:

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

		elif self.ctx.version == 3:

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
		
		if self.ctx.version == 5:

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
			
		elif self.ctx.version == 3:
			
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
			raise WeaveException("Storage version %s not supported" % self.ctx.version)

		
		return v


	def encrypt(self, plaintextData, encryptionLabel=None):
		"""Given a plaintext object, encrypt it and return the ciphertext value."""

		logging.debug("encrypt()")
		logging.debug("plaintext:\n" + pprint.pformat(plaintextData))
		
		if self.ctx.version == 5:

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
			raise WeaveException("Encryption not supported for storage version %s" % self.ctx.version)


	def get(self, collection, id, decrypt=True):
		wbo = self.ctx.get(collection, id)

		if ( decrypt ):
			wbo = self.decrypt_weave_basic_object(wbo, collection)

		return wbo

		
	def get_collection_ids(collection, params=None):
		return self.ctx.get_collection_ids(collection, params=params)


	def get_collection(self, collection, decrypt=True):
		colWbo = self.ctx.get_collection(collection)

		colWboDecrypt
		if ( decrypt ):
			for wbo in colWbo:
				colWboDecrypt.append(self.decrypt_weave_basic_object(wbo))
			
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
	parser.add_option("-s", "--server", help="server URL, if you aren't using services.mozilla.com", dest="server")
	parser.add_option("-u", "--user", help="username", dest="username")
	parser.add_option("-p", "--password", help="password (sent securely to server)", dest="password")
	parser.add_option("-k", "--passphrase", help="passphrase (used locally)", dest="passphrase")
	parser.add_option("-K", "--credentialfile", help="get username, password, and passphrase from this credential file (as name=value lines)", dest="credentialfile")
	parser.add_option("-a", "--authenticate", help="get authentication token from v6 token server", dest="authenticate")    
	parser.add_option("-c", "--collection", help="collection", dest="collection")
	parser.add_option("-i", "--id", help="object ID", dest="id")
	parser.add_option("-f", "--format", help="format (default is text; options are text, json, xml)", default="text", dest="format")
	parser.add_option("-v", "--verbose", help="print verbose logging", action="store_true", dest="verbose")
	parser.add_option("-l", "--log-level", help="set log level (critical|error|warn|info|debug)", dest="loglevel")
	parser.add_option("-m", "--modify", help="Update collection, or single item, with given value in JSON format. Requires -c and optionally -i", dest="modify")


	(options, args) = parser.parse_args()

	if options.credentialfile:
		if options.username:
			print "The 'username' option must not be used when a credential file is provided."
			sys.exit(1)
		if options.password:
			print "The 'password' option must not be used when a credential file is provided."
			sys.exit(1)
		if options.passphrase:
			print "The 'passphrase' option must not be used when a credential file is provided."
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
					elif key == 'passphrase':
						options.passphrase = value.strip()
		except Exception, e:
			import traceback
			traceback.print_exc(e)
			print e
			sys.exit(1)

	if options.authenticate:
		if not ( options.server and options.username and options.password ):
			print "server, username and password are required arguments. Use -h for help."
			sys.exit(1)
	else: 
		if not ( options.server and options.username and options.password and options.passphrase ):
			print "server, username, password and passphrase/synckey are required arguments. Use -h for help."
			sys.exit(1)

	if options.modify and not options.collection:
		print "The modify argument requires that the collection argument is also set. Use -h for help."
		sys.exit(1)

	formatter = FORMATTERS[options.format]

	if options.loglevel:
		logging.basicConfig(level = str.upper(options.loglevel))
	elif options.verbose:
		logging.basicConfig(level = logging.DEBUG)
	else:
		logging.basicConfig(level = logging.ERROR)

	# Create a storage context: this will control all the sending and retrieving of data from the server
	if options.server:
		rootServer = options.server
	else:
		rootServer="https://auth.services.mozilla.com"

	weaveClient = WeaveClient(rootServer, options.username, options.password, options.passphrase)
    
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
			wbo = weaveClient.get(options.collection, options.id)
			logging.debug("item:\n" + pprint.pformat(wbo))
			if len(wbo['payload']) > 0:
				# Empty length payload is legal: indicates a deleted item
				itemObject = json.loads(wbo['payload'])
				formatter.format(itemObject)
				
		else:
			# Collection
			colWbo = weaveClient.get_collection(options.collection)
			logging.debug("collection:\n" + pprint.pformat(wbo))
			for wbo in colWbo:
				if len(wbo['payload']) > 0:
					itemObject = json.loads(wbo['payload'])
					formatter.format(itemObject)
			
	else:
		print "No command provided: use -h for help"
