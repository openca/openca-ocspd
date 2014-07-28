#!/bin/sh

echo "Requesting for a good response:"
openssl ocsp -issuer certs/cacert.pem -serial 1 -url http://localhost:2560
echo
echo "Requesting for an unknown response:"
openssl ocsp -issuer certs/cacert.pem -serial 2 -url http://localhost:2560

exit 0;

