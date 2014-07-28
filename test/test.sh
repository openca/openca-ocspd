#!/bin/bash

echo
echo "OCSP Test Script"
echo "(c) 2006 by Massimiliano Pala and OpenCA Team"
echo

# if [ $# -lt 3 ] ; then
# 	echo "Usage: $0 <CAfile> <Issuer_Cert> <URL>"
# 	echo
# 	echo "   example:  $0 ca-bundle.pem cacert.pem http://localhost:2560/"
# 	echo
# 	exit 0
# fi

cabundle=data/europki_root_ca_cert.pem
cacert=data/europki_root_ca_cert.pem
url=http://localhost:2560/

if [ "0$1" -gt 0 ] ; then
	nreq=$1;
else
	nreq=78;
fi

for ser in 123 ; do
	echo "Test $nreq requests (serial $ser):"
	echo -n "["
	time {
		for((i=0;i<$nreq;i++)); do
			openssl ocsp -CAfile $cabundle \
				-url $url \
				-issuer $cacert \
				-serial $ser 2>/dev/null >/dev/null
				# -cert test/ocspd_cert.pem 2>/dev/null >/dev/null
			if [ $? = 0 ] ; then
				echo -n .
			else
				echo -n $?
			fi
		done
	}
	echo  "]"
	echo
done

exit
