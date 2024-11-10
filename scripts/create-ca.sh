
cd ~/certs
echo "removing old certs"
rm *

openssl genrsa -des3 -out myCA.key 2048

openssl dhparam -out dh.pem 2048

openssl req -x509 -new -nodes -key myCA.key -sha256 -days 1825 -out myCA.pem
sudo apt-get install -y ca-certificates
sudo cp myCA.pem /usr/local/share/ca-certificates/myCA.crt
sudo update-ca-certificates
