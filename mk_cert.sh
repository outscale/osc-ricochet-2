#!/bin/sh
openssl req -new  -nodes -subj "/C=FR/ST=France/L=Paris/O=Dis/CN=www.outscale.com" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"  -newkey rsa:4096 -keyout cert.key -out cert.csr
openssl x509 -req -days 365 -in cert.csr -signkey cert.key -out cert.crt -copy_extensions copy
openssl x509 -text -noout -in cert.crt
