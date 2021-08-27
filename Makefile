all: ca.key ca.pem wildcard.bt.pem

wildcard.bt.pem: ca.key ca.pem
	go run -race . gencert '*.bt' '*.bt' '*.ih.bt' '*.pk.bt' > $@

ca.key:
	openssl genrsa -out $@

ca.pem: ca.key
	openssl req -x509 -new -key $< -out $@ -subj '/CN=btlink root CA' \
		-addext 'nameConstraints=critical, permitted;DNS:bt,permitted;DNS:localhost'

.PHONY: add-trusted-cert
add-trusted-cert: ca.pem
	sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" ca.pem

# Generates a certificate for an arbitrary domain
%.pem: ca.key ca.pem
	godo -race . gencert $* $* > $@
