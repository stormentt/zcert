# Overview
Zcert is a tool for managing a certificate authority over a network. It only deals with ed25519 certificates.

## Quick Start
```bash
# To create a certificate authority & initialize the database
zcert init

# To generate a shared authentication key for message authentication codes
zcert authkey generate

# To start listening for requests
zcert server

# To have the server sign a certificate signing request
zcert client sign --in request.csr
```

## Server Usage
First run `zcert init` to initialize the database and create the certificate authority. Then run `zcert server` to listen for HTTP connections.

zcert has 2 routes

| Method | Privileged | Path | Function |
|--------|------------|------|----------|
| GET    | No         | /ca  | shows the certificate authority |
| POST   | Yes        | /sign | signs the certificate signing request to create a signed certificate |

If a route is privileged, zcert will expect and validate a message authentication code. 

## Client Usage
Currently zcert has 1 client command, `zcert client sign`. This command will take a certificate signing request, send it to the server, and write the signed certificate out. It can read and write from files or stdin/stdout.

## Configuration
The configuration file for zcert is named zcert.yml. `zcert authkey generate` can be used to generate a suitable key for the message authentication codes. 
