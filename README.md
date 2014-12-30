weaveclient-python
==================

Weave Sync/Firefox Sync client library written in Python.

## Features
* Compatible with Weave Sync v1.1 (pre Firefox 29) an v1.5 (FxA)
* Encrypt/Decrypt data stored on Weave Sync server (read and write)
* Commandline client

## Library

### Weave Client

```python
import weaveclient as wc

wc_params = {
    'api_version':    "V1_5",
    'account_server': "https://api.accounts.firefox.com",
    'token_server':   "https://token.services.mozilla.com",
    'username':       "username",
    'password':       "password"
}

weave_client = wc.WeaveClient.get_instance(wc_params)

collection = "bookmarks";

colWbo = weave_client.get_collection(collection)
for wbo in colWbo:
    if len(wbo['payload']) > 0:
       print wbo['payload']

id = "FprxRkbQsyKe" #Base64 encoded object id (unique within collection)
wbo = weave_client.get(collection, id)
if len(wbo['payload']) > 0:
   print wbo['payload']
```

## Commandline

### Weave Client
```
Usage: weaveclient [options]

Options:
  -h, --help            show this help message and exit
  -s ACCOUNT_SERVER, --account-server=ACCOUNT_SERVER
                        account server url if you are not using defaults
  -t TOKEN_SERVER, --token-server=TOKEN_SERVER
                        sync token server url if you are not using defaults
  -u USERNAME, --user=USERNAME
                        username
  -p PASSWORD, --password=PASSWORD
                        password (sent securely to server)
  -k SYNCKEY, --synckey=SYNCKEY
                        synckey (used locally)
  -K CREDENTIALFILE, --credentialfile=CREDENTIALFILE
                        get username, password, and synckey from this
                        credential file (as name=value lines)
  -c COLLECTION, --collection=COLLECTION
                        collection
  -i ID, --id=ID        object ID
  -f FORMAT, --format=FORMAT
                        format (json|xml|text). Defaults to json
  -v API_VERSION, --api-version=API_VERSION
                        weave sync storage api version (V1_1|V1_5). Defaults
                        to V1_1
  -l LOGLEVEL, --log-level=LOGLEVEL
                        set log level (critical|error|warn|info|debug).
                        Defaults to info
  -m MODIFY, --modify=MODIFY
                        Update collection, or single item, with given value in
                        JSON format. Requires -c and optionally -i
  --plaintext           plaintext collection, don't decrypt
  --test-mode           use test data
```
