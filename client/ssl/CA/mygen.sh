#!/bin/sh
rm -rf index newcerts/*.pem serial *.req *.key *.crt crl.prm

touch index
echo "01" > serial

#password created with following command: openssl rand -base64 18
PASSWORD="rENurzt5gO9mYmq0xGikdX18"
CA_CONFIG=thawte.conf
USER_CONFIG=kaspersky.conf

echo "Generating CA"
cat thawte.conf > sslconf_use.txt 
echo "CN=PolarSSL Test CA" >> sslconf_use.txt

openssl req -config $CA_CONFIG -days 3653 -x509 -newkey rsa:2048 \
            -set_serial 1 -text -keyout ca.key -out ca.crt -passout pass:$PASSWORD

echo "Generating private keys"
openssl genrsa -out server.key 2048
openssl genrsa -out client.key 2048

echo "Generating requests"
#cat thawte.conf > sslconf_use.txt;echo "CN=Server" >> sslconf_use.txt
openssl req -config $USER_CONFIG -new -key server.key -out server.req

#cat thawte.conf > sslconf_use.txt;echo "CN=Client" >> sslconf_use.txt
openssl req -config $USER_CONFIG -new -key client.key -out client.req


echo "Signing requests"
for i in server client;
do
  openssl ca -config $CA_CONFIG -out $i.crt -passin pass:$PASSWORD \
	-batch -in $i.req
done


rm -f *.old *.req sslconf_use.txt
