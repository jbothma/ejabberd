# Based on http://www.mcgill.org.za/software/ca/instant-ssl-ca

all: node1.pem node2.pem

node1.pem: node1.cnf ca.pem
	openssl req -config node1.cnf -nodes -new -keyout node1.key -out node1.csr
	yes y | openssl ca -config ca.cnf -keyfile ca.key -cert ca.crt -passin '' -key '' -out node1.crt -in node1.csr
	cat node1.key node1.crt > node1.pem

node2.pem: node2.cnf ca.pem
	openssl req -config node2.cnf -nodes -new -keyout node2.key -out node2.csr
	yes y | openssl ca -config ca.cnf -keyfile ca.key -cert ca.crt -passin '' -key '' -out node2.crt -in node2.csr
	cat node2.key node2.crt > node2.pem

ca.pem: ca.cnf index.txt index.txt.attr serial
	openssl req -config ca.cnf -nodes -new -x509 -keyout ca.key -out ca.crt -days 10950
	cat ca.key ca.crt > ca.pem

index.txt:
	touch index.txt

index.txt.attr:
	touch index.txt.attr

serial:
	echo 01 -> serial

install: all
	cp node1.pem node2.pem ca.pem /tmp

clean:
	rm *.pem *.crt *.csr *.key index.txt index.txt.attr* serial
