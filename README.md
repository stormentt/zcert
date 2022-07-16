# Overview
Zcert is a tool for managing a certificate authority over a network. It only deals with ed25519 certificates.

## Usage
```bash
# To create a certificate authority
zcert init

# To start listening for requests
zcert serve

# To have the server sign a certificate
zcert client sign /path/to/certficate.crt
```

## Server
The zcert server is an HTTP api that uses blake2b hmacs to validate requests. 
