There is no password/encryption for any of the private keys or the pfx file.

the entire cert chain is in the pfx file

FOR DEVELOPMENT replace ./ca with ./ca-test

./ca/root/cert contains the root level CA certificate PEM format
./ca/root/private contains the private keys PEM format

./ca/idensign/cert contains the intermediate level idensign CA certificate in PEM format as well as the comodosign assurance services cert
./ca/idensign/private contains the intermediate level idensign CA key in PEM format as well as the comodosign assurance services key

./ca/objsign/cert contains the intermediate level objsign CA certificate in PEM format
./ca/objsign/private contains the intermediate level objsign CA key in PEM format
