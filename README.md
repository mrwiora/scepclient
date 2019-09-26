# scepclient

extract of relevant code part from https://github.com/micromdm/micromdm

currently the software is able to:
- requesting the first certificate using the challenge passphrase
- requesting the second certificate

requesting any further certificate does not work

helpers
```
go get github.com/pkg/errors
go get github.com/go-kit/kit/log
go get github.com/fullsailor/pkcs7

# startparameter
-server-url http://10.6.115.153/certsrv/mscep/mscep.dll -debug -private-key /home/pix/private.pem -challenge 2EB13806806917D0

# verify x509 cert
openssl x509 -in client.pem -text -noout

# verify csr
openssl req -in csr.pem -text -verify -subject
```