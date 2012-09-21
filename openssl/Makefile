# Modified from http://www.mcgill.org.za/software/ca/instant-ssl-ca

all: node1.pem node2.pem

node1.pem: node1.conf ca.crt
	openssl req -config node1.conf -nodes -new -keyout node1.key -out node1.csr
	openssl ca -config openssl.cnf -keyfile ca.key -cert ca.crt -passin '' -key '' -out node1.crt -in node1.csr
	cat node1.key node1.crt > node1.pem

node2.pem: node2.conf ca.crt

ca.crt: openssl.cnf index.txt index.txt.attr serial
	KEY_COMMONNAME="my ca" openssl req -config openssl.cnf -nodes -new -x509 -keyout ca.key -out ca.crt -days 10950

index.txt:
	touch index.txt

index.txt.attr:
	touch index.txt.attr

serial:
	echo 01 -> serial

clean:
	rm ca.crt ca.key node1.csr node1.key
