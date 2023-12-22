#!/bin/bash

# Prompt the user for certificate details
echo "Enter certificate details:"
read -p "Organization (O): " ORGANIZATION
read -p "Common Name (CN): " COMMON_NAME
read -p "Country (C): " COUNTRY
read -p "State (ST): " STATE

# Set the output paths for the private key and certificate
PRIVATE_KEY="private_key.pem"
CERTIFICATE="certificate.pem"

# Set the subject information for the certificate
SUBJECT="/C=$COUNTRY/ST=$STATE/O=$ORGANIZATION/CN=$COMMON_NAME"

# Generate a private key
openssl genpkey -algorithm RSA -out "$PRIVATE_KEY"

# Generate a self-signed certificate using the private key
openssl req -new -x509 -key "$PRIVATE_KEY" -out "$CERTIFICATE" -subj "$SUBJECT"

if [ $? -eq 0 ]; then
    echo "Certificate successfully created: $CERTIFICATE"
else
    echo "Error: Failed to create the certificate."
fi
