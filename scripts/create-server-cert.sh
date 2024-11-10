
ln -sf $PWD/scripts/x509-v3-cert-ext-config.txt ~/certs

cd ~/certs

openssl genrsa -out server.test.key 2048

openssl req -new -key server.test.key -out server.test.csr

openssl x509 -req -in server.test.csr -CA myCA.pem -CAkey myCA.key \
-CAcreateserial -out server.test.crt -days 825 -sha256 -extfile x509-v3-cert-ext-config.txt
