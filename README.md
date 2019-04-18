# Authenticating to a [Handle.net](https://www.handle.net) Server to Use the REST interface with a Public Key Authentication

The documentation on this is rather terse, and some of the [sources](#sources) are still helpful but do not work anymore on contemporary Python.  The Handle.net [manual](http://www.handle.net/tech_manual/HN_Tech_Manual_9.pdf) and the [documentation](http://www.handle.net/hnr_documentation.html) in general state things correctly, but in my case needed some research.

According to chapter 14 of the manual, one can authenticate to the Handle.net server using a challenge and using client-side certificates.  Both need an unencrypted key file for the respective administrator, at least if you use Python and PyCryptodome.


We first prepare the keys, then we illustrate connecting to a handle server.

This was tested on Handle.net softare 9.1, but should work with version 8 as well, I suppose.  Python 3.6+ should work.


# Preliminary: Get Software

Install [requests](https://pypi.org/project/requests/) for connectivity, e.g.

```bash
pip install requests
```

When using challenge authentication, also install [PyCryptodome](https://pypi.org/project/pycryptodome/) for crytography: 

```bash
pip install pycryptodomex
```


Also make sure OpenSSL ist installed on the system.

We assume that Handle.net software is at `/opt/handle`.


# Preliminarey: Prepare Keys and Certificates

We use an administrator handle `300:10932/ADMIN` as an example.  This has to be adapted, of course.

Let us assume we already generated keys for this user using the Handle.net scripts; we assume this is a DSA key.  Probably, this key has a passphrase, with which Python cannot deal, and it is in the wrong format.  Conversion is possible with the Handle.net scripts, and it is sufficient for challenge authentication.

```bash
/opt/handle/bin/hdl-convert-key private.key > private.pem
/opt/handle/bin/hdl-convert-key public.key > public.pem
```

For certificate authentication, we also need a certificate request.  The [manual](http://www.handle.net/tech_manual/HN_Tech_Manual_9.pdf) (14.6.2) states that “[t]he public key of the certificate must correspond to the HS_PUBKEY value stored at that handle and index.”  This is is achieved by using the private key as the basis for the generation of a certificate: 

```bash
openssl req -new -x509 -key private.pem -subj '/UID=300:10932\/ADMIN' \
  -days 3652 -out cert.pem
```

# Connecting 

As an example we now query the server for its handles.  This needs authentication.

## Connecting with client-side certificates

```python
#!/usr/bin/env python

# monkey patch ssl to allow hostname mismatches:
import ssl
ssl.match_hostname = lambda cert, hostname: True

import requests

# adjust these:
KEY_FILE = "private.pem"
CERTIFICATE = "cert.pem"
SERVER = "https://telemann.local:8000"
PREFIX = "10932"
URL = f"{SERVER}/api/handles?prefix={PREFIX}"
SERVER_CERTIFICATE = "serverCertificate.pem"  # in your server home directory

# header to trigger certificate processing:
AUTH_H = {'Authorization': 'Handle clientCert="true"'}

# connect:
resp = requests.get(
    URL, verify=SERVER_CERTIFICATE,
    # UID is in the certificate:
    cert=(CERTIFICATE, KEY_FILE),
    headers=AUTH_H)
print(resp.status_code)  # if this is 200, we are authenticated
print(resp.headers)      # look at the response
print(resp.content)

```


## Connecting with keys and challenge

The important points are:

- extracting `sessionId` and `nonce` from the challenge,
- generating a client nonce `cnonce`,
- signing the concatenation of nonce and cnonce,
- building the header.


```python
#!/usr/bin/env python
import base64
import re
import sys

# monkey patch ssl to allow hostname mismatches:
import ssl
ssl.match_hostname = lambda cert, hostname: True

import requests
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import DSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import DSS


# adjust these:
KEY_FILE = "private.pem"
SERVER = "https://telemann.local:8000"
PREFIX = "10932"
ADMIN = "ADMIN"
INDEX = 300
ADMIN_ID = f"{INDEX}:{PREFIX}/{ADMIN}"
SERVER_CERTIFICATE = "serverCertificate.pem"  # in your server home directory

# example, query for handles of a prefix:
URL = f"{SERVER}/api/handles?prefix={PREFIX}"

EIGHT_BIT_ENCODING = "latin1"  # for converting bytes and strings


# first get info on session and authentication:
resp = requests.get(URL, verify=SERVER_CERTIFICATE)
print(resp.status_code)  # should be 401, insufficient permissions
response_header = resp.headers["WWW-Authenticate"]

# get data from header
nonce_encoded = re.search(r'(?<=nonce=").*?(?=")', response_header)[0]
nonce_bytes = base64.b64decode(nonce_encoded.encode(EIGHT_BIT_ENCODING))
session_id = re.search(r'(?<=sessionId=").*?(?=")', response_header)[0]
sys.stderr.write(f"NONCE: {nonce_encoded}, SESSION: {session_id}\n")

# generate client nonce:
cnonce_bytes = get_random_bytes(16)
cnonce_encoded = base64.b64encode(cnonce_bytes).decode(EIGHT_BIT_ENCODING)
sys.stderr.write(f"NONCE # {len(nonce_bytes)}  CNONCE # {len(cnonce_bytes)}\n")

# sign nonce + cnonce concatenation:
to_sign = SHA256.new(nonce_bytes + cnonce_bytes)
with open(KEY_FILE, "r") as key_file:
    PRIVATE_KEY = DSA.import_key(key_file.read())
signer = DSS.new(PRIVATE_KEY, 'fips-186-3',
                 encoding="der")
sig = base64.encodebytes(signer.sign(to_sign)).decode("ASCII").strip()

# build header:
headers = {'Authorization':
           f'Handle sessionId="{session_id}", ' +
           f'id="{ADMIN_ID}", type="HS_PUBKEY", ' +
           f'cnonce="{cnonce_encoded}", alg="SHA256", signature="{sig}"'}
# print(headers)

# the status code should now be 200:
print(requests.get(URL, verify=SERVER_CERTIFICATE, headers=headers).status_code)
headers = {'Authorization':
               f'Handle sessionId="{session_id}"'}
# we can still continue authenticated for some time by holding on to the session:
print(requests.get(URL, verify=SERVER_CERTIFICATE, headers=headers).status_code)
```


## Why monkey-patch  and use `verify=SERVER_CERTIFICATE`?

All scripts use `verify=verify=SERVER_CERTIFICATE` to verify the Handle.net server certificate.  Unfortunately, the automatically generated server certificate (see [manual](http://www.handle.net/tech_manual/HN_Tech_Manual_9.pdf), p. 20) does not contain the hostname, but Python [checks the hostname](https://urllib3.readthedocs.io/en/latest/user-guide.html#ssl).  The [monkey patch](https://stackoverflow.com/questions/28768530/certificateerror-hostname-doesnt-match) above helps; the only alternative would be to use `verify=False`, or to use a well-signed Handle.net server certificate.

# Sources

- [examples by Alan Smith](https://github.com/theNBS/handleserver-samples/), for Python 2 and PyCrypto.
- [Post by Robert R Tupelo-Schneck](http://www.handle.net/mail-archive/handle-info/msg00816.html) on the Handle.net mailing list.
- [Working with Persistent Identifiers – Hands-on](https://github.com/EUDAT-Training/B2SAFE-B2STAGE-Training/blob/master/07a-Working-with-PIDs_CURL.md) by EUDAT-Training shows how to use certificates with [curl](https://curl.haxx.se/).
- [CertificateError: hostname doesn't match](https://stackoverflow.com/questions/28768530/certificateerror-hostname-doesnt-match) on StackOverflow explains how to circumvent Python SSL host name validation.
