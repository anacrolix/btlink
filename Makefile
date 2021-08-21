ca.key:
	openssl genrsa -out $@

ca.pem: ca.key
	openssl req -x509 -new -key $< -out $@

trust-%:
	sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" $*

%.pem: ca.key ca.pem
	godo -race . gencert $* > $@
