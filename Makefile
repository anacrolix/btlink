all: ca.key ca.pem wildcard.bt.pem localhost.pem

wildcard.bt.pem: ca.key ca.pem
	# Due to https://bugzilla.mozilla.org/show_bug.cgi?id=1728009 we need to put the least specific
	# wildcards last.
	go run -race . gencert  '*.ih.bt' '*.pk.bt' '*.ih.bt' '*.bt' > $@

ca.key:
	openssl genrsa -out $@

ca.pem: ca.key
	openssl req -x509 -new -key $< -out $@ -subj '/CN=btlink root CA' \
	# Firefox doesn't like name constraints
#		-addext 'nameConstraints=critical, permitted;DNS:bt,permitted;DNS:localhost'

.PHONY: add-trusted-cert
add-trusted-cert: ca.pem
	sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" ca.pem

# Generates a certificate for an arbitrary domain
%.pem: ca.key ca.pem
	godo -race . gencert $* $* > $@
