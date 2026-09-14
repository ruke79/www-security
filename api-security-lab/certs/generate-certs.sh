#!/usr/bin/env bash
#
# Chapter 4 - Mutual Authentication with TLS
#
# Generates all the key material needed to exercise the mTLS demo:
#   - server-keystore.p12    server's own RSA keypair + self-signed cert
#   - client-keystore.p12    client's RSA keypair + self-signed cert (for curl --cert-type P12 --cert)
#   - client-cert.pem / client-key.pem   PEM versions of the above (for curl --cert/--key)
#   - server-truststore.p12  a truststore containing the CLIENT's certificate, so the
#                            server will accept and trust it during the TLS handshake
#
# Run this script from the project root, i.e.:
#   ./certs/generate-certs.sh
#
# It writes all output files into this same certs/ directory, matching the
# relative paths configured in application.yml (app.mtls.keystore.path etc).
set -euo pipefail

cd "$(dirname "$0")"

PASSWORD=changeit
SERVER_ALIAS=server
CLIENT_ALIAS=client
DAYS=3650

echo "==> Cleaning up any previous key material"
rm -f server-keystore.p12 server-truststore.p12 client-keystore.p12 client-cert.pem client-key.pem client-cert.p12

echo "==> Generating server keypair + self-signed certificate (server-keystore.p12)"
keytool -genkeypair \
  -alias "$SERVER_ALIAS" \
  -keyalg RSA -keysize 2048 \
  -validity $DAYS \
  -keystore server-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" -keypass "$PASSWORD" \
  -dname "CN=localhost, OU=Demo, O=Advanced API Security, C=US" \
  -ext "SAN=dns:localhost,ip:127.0.0.1"

echo "==> Generating client keypair + self-signed certificate (client-keystore.p12)"
keytool -genkeypair \
  -alias "$CLIENT_ALIAS" \
  -keyalg RSA -keysize 2048 \
  -validity $DAYS \
  -keystore client-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" -keypass "$PASSWORD" \
  -dname "CN=demo-client, OU=Demo, O=Advanced API Security, C=US"

echo "==> Exporting the client's certificate so it can be imported into the server's truststore"
keytool -exportcert \
  -alias "$CLIENT_ALIAS" \
  -keystore client-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -file client-cert.der

echo "==> Building server truststore containing the client's certificate"
keytool -importcert \
  -alias "$CLIENT_ALIAS" \
  -keystore server-truststore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -file client-cert.der \
  -noprompt

echo "==> Exporting client cert/key as PEM (for curl --cert/--key, easier than PKCS12 with some curl builds)"
openssl pkcs12 -in client-keystore.p12 -passin pass:"$PASSWORD" \
  -nocerts -nodes -out client-key.pem -legacy 2>/dev/null || \
openssl pkcs12 -in client-keystore.p12 -passin pass:"$PASSWORD" \
  -nocerts -nodes -out client-key.pem

openssl pkcs12 -in client-keystore.p12 -passin pass:"$PASSWORD" \
  -clcerts -nokeys -out client-cert.pem -legacy 2>/dev/null || \
openssl pkcs12 -in client-keystore.p12 -passin pass:"$PASSWORD" \
  -clcerts -nokeys -out client-cert.pem

rm -f client-cert.der

echo ""
echo "==> Done. Generated in $(pwd):"
ls -1 *.p12 *.pem 2>/dev/null

cat <<'EOF'

Next steps:
  1. Start the app:  mvn spring-boot:run
  2. Call the mTLS endpoint presenting the client certificate, e.g.:

     curl -v --cert certs/client-cert.pem --key certs/client-key.pem \
          --cacert certs/... (or -k to skip server cert validation for this demo) \
          https://localhost:8443/api/ch4/whoami

     (Using -k is the simplest option for a local demo since the server
     certificate is self-signed and not in your system trust store.)
EOF
