# TACACS+ over TLS Support

This document describes the implementation of TACACS+ over TLS as specified in [IETF draft-ietf-opsawg-tacacs-tls13-07](https://www.ietf.org/archive/id/draft-ietf-opsawg-tacacs-tls13-07.html).

## Overview

The TACACS+ protocol traditionally operates over a TCP connection without encryption, relying on a shared secret for packet encryption. This implementation adds support for TACACS+ over TLS 1.3, providing stronger security through:

- Transport layer encryption using TLS 1.3
- Certificate-based authentication with Subject Alternative Names (SAN)
- Optional mutual TLS authentication

## Command-line Options

The following command-line options have been added to the server to support TLS:

```
  -tls                        Enable TLS support as per IETF draft-ietf-opsawg-tacacs-tls13-07
  -tls-cert string            Path to TLS certificate file
  -tls-key string             Path to TLS key file
  -tls-ca string              Path to TLS CA certificate file for client certificate validation
  -tls-require-client-cert    Require client certificates for TLS connections
```

## Port Configuration

When using TLS, IANA recommends a different port (tacacss) for TACACS+ over TLS.

```
  -address ":49"              Standard TACACS+ port
  -address ":XXXX"            Alternative TACACS+ port (tacacss:300)
                              In this document, we will use port 6653 for testing
```

## Certificate Generation with SAN Extensions

**IMPORTANT**: Modern TLS implementations require certificates with Subject Alternative Names (SAN) extensions. Certificates that rely only on the Common Name (CN) field will fail with errors like:

```
tls: failed to verify certificate: x509: certificate relies on legacy Common Name field, use SANs instead
```

## Setting up a test environment
### Generate CA Certificate

```bash
# Generate CA private key
openssl genrsa -out ca.key 2048

# Generate CA certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt -subj "/CN=TACACS_Test_CA"
```

### Generate Server Certificate with SAN Extensions

First, create a configuration file for the server certificate:

```bash
cat > server.conf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = ::1
IP.2 = 127.0.0.1
EOF
```

Then generate the server certificate:

```bash
# Generate server private key
openssl genrsa -out server.key 2048

# Generate server certificate signing request (CSR) with SAN configuration
openssl req -new -key server.key -out server.csr -config server.conf

# Sign the server certificate with SAN extensions
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extensions v3_req -extfile server.conf
```

### Generate Client Certificate with SAN Extensions (for mutual TLS)

First, create a configuration file for the client certificate:

```bash
cat > client.conf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = ::1
IP.2 = 127.0.0.1
EOF
```

Then generate the client certificate:

```bash
# Generate client private key
openssl genrsa -out client.key 2048

# Generate client certificate signing request (CSR) with SAN configuration
openssl req -new -key client.key -out client.csr -config client.conf

# Sign the client certificate with SAN extensions
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256 -extensions v3_req -extfile client.conf
```

### Verify Certificate SAN Extensions

You can verify that your certificates include proper SAN extensions:

```bash
# Verify server certificate SAN extensions
openssl x509 -in server.crt -text -noout | grep -A 3 "Subject Alternative Name"

# Expected output:
# X509v3 Subject Alternative Name:
#     DNS:localhost, IP Address:0:0:0:0:0:0:0:1, IP Address:127.0.0.1

# Verify client certificate SAN extensions
openssl x509 -in client.crt -text -noout | grep -A 3 "Subject Alternative Name"
```

### Verify Certificate Chain

Ensure the certificate chain is valid:

```bash
# Verify server certificate chain
openssl verify -CAfile ca.crt server.crt
# Expected: server.crt: OK

# Verify client certificate chain
openssl verify -CAfile ca.crt client.crt
# Expected: client.crt: OK
```

## Running the Server with TLS

### Basic TLS Server (Server Certificate Only)

```bash
./server -tls -tls-cert server.crt -tls-key server.key -address ":6653"
```

### TLS Server with Client Certificate Validation

```bash
./server -tls -tls-cert server.crt -tls-key server.key -tls-ca ca.crt -address ":6653"
```

### TLS Server Requiring Client Certificates (Mutual TLS)

```bash
./server -tls -tls-cert server.crt -tls-key server.key -tls-ca ca.crt -tls-require-client-cert -address ":6653"
```

## Running the Client with TLS

### Basic TLS Client (Server Certificate Validation Only)

```bash
./client -tls -username cisco -address "localhost:6653" -tls-ca ca.crt
```

### TLS Client with Client Certificate (Mutual TLS)

```bash
./client -tls -username cisco -address "localhost:6653" \
  -tls-ca ca.crt -tls-cert client.crt -tls-key client.key
```

### TLS Client with Insecure Skip Verify (Testing Only)

```bash
./client -tls -username cisco -address "localhost:6653" -tls-insecure-skip-verify
```

**Warning**: Never use `-tls-insecure-skip-verify` in production environments.

## Testing TLS Configuration

### Test Certificate Chain with OpenSSL

```bash
# Test TLS connection to server
echo | timeout 5 openssl s_client -connect localhost:6653 -CAfile ca.crt -servername localhost

# Expected output should include:
# Verification: OK
# Verify return code: 0 (ok)
```

### Test Mutual TLS with OpenSSL

```bash
# Test TLS connection with client certificate
echo | timeout 5 openssl s_client -connect localhost:6653 -CAfile ca.crt \
  -cert client.crt -key client.key -servername localhost
```

## Implementation Details

The TLS implementation follows these key principles:

1. **TLS Version**: Requires TLS 1.3 as specified in the IETF draft
2. **Certificate Validation**: Properly validates server and client certificates with SAN extensions
3. **Packet Processing**: TACACS+ packets are sent unencrypted within the TLS tunnel (with UnencryptedFlag set)
4. **Backward Compatibility**: The server can still operate in non-TLS mode for backward compatibility

## Debugging TLS Issues

When troubleshooting TACACS+ over TLS problems, follow this systematic debugging approach:

### 1. Verify Certificate Chain

First, ensure all certificates are properly generated and linked:

```bash
# Verify server certificate chain
openssl verify -CAfile ca.crt server.crt
# Expected: server.crt: OK

# Verify client certificate chain
openssl verify -CAfile ca.crt client.crt
# Expected: client.crt: OK
```

### 2. Check Certificate SAN Extensions

Modern TLS requires Subject Alternative Names (SAN). Verify they exist:

```bash
# Check server certificate SAN extensions
openssl x509 -in server.crt -text -noout | grep -A 3 "Subject Alternative Name"

# Expected output:
# X509v3 Subject Alternative Name:
#     DNS:localhost, IP Address:0:0:0:0:0:0:0:1, IP Address:127.0.0.1

# Check client certificate SAN extensions
openssl x509 -in client.crt -text -noout | grep -A 3 "Subject Alternative Name"
```

### 3. Test TLS Connection with OpenSSL s_client

Before testing with TACACS+ client/server, verify the TLS handshake works:

```bash
# Test basic TLS connection (server certificate validation)
echo | timeout 5 openssl s_client -connect localhost:49 -CAfile ca.crt -servername localhost

# Test mutual TLS connection (client certificate authentication)
echo | timeout 5 openssl s_client -connect localhost:49 -CAfile ca.crt \
  -cert client.crt -key client.key -servername localhost
```

**What to look for in s_client output:**
- `Verification: OK` - Certificate chain is valid
- `Verify return code: 0 (ok)` - No certificate errors
- `Protocol: TLSv1.3` - TLS 1.3 is being used
- Certificate chain section showing your certificates

### 4. Enable Detailed TLS Debugging

For more detailed TLS debugging, add verbose flags to openssl s_client:

```bash
# Verbose TLS debugging
echo | timeout 5 openssl s_client -connect localhost:49 -CAfile ca.crt \
  -servername localhost -verify 3 -debug -msg

# This shows:
# - TLS handshake messages
# - Certificate verification details
# - Protocol negotiation
# - Cipher suite selection
```

### 5. Debug TACACS+ Packet Issues

If TLS connects but TACACS+ fails, check packet-level issues:

```bash
# Add debugging to see detailed error messages
# Look for errors like:
# "bad secret detected authenstart - expected len: 471, got: 10 (user:52 port:156 remAddr:205 data:58)"

# This indicates:
# - expected len: Sum of length fields from packet header
# - got: Actual parsed field lengths
# - Large garbage values suggest packet corruption or wrong encryption/decryption
```

### 6. Verify Server Logs

Check server logs for detailed error information:

```bash
# Look for these log patterns:
DEBUG: prefix secret provider matches remote [::1] against prefix [::/0]
ERROR: closing connection, unable to read, remote error: tls: bad certificate
ERROR: closing connection, unable to read, tls: failed to verify certificate: x509: certificate signed by unknown authority
```

### 7. Test Network Connectivity

Ensure basic network connectivity works:

```bash
# Test if server port is accessible
nc -zv localhost 6653
# Expected: Connection to localhost 49 port [tcp/*] succeeded!

# Test if TLS port responds
echo | timeout 2 openssl s_client -connect localhost:6653
# Should establish connection (even if certificate verification fails)
```

### 8. Common Debugging Scenarios

#### Scenario 1: Certificate SAN Extension Missing
**Symptoms:**
```
tls: failed to verify certificate: x509: certificate relies on legacy Common Name field, use SANs instead
```

**Debug Steps:**
1. Check certificate SAN extensions with `openssl x509 -text`
2. If missing, regenerate certificates with proper SAN configuration
3. Verify both server and client certificates have SAN extensions

#### Scenario 2: Certificate Authority Trust Issues
**Symptoms:**
```
tls: failed to verify certificate: x509: certificate signed by unknown authority
```

**Debug Steps:**
1. Verify certificate chain with `openssl verify`
2. Test TLS connection with `openssl s_client`
3. Check client has correct `-tls-ca` parameter
4. Check server has correct `-tls-ca` parameter for client validation

#### Scenario 3: Packet Length Mismatch
**Symptoms:**
```
bad secret detected authenstart - expected len: 471, got: 10 (user:52 port:156 remAddr:205 data:58)
```

**Debug Steps:**
1. Large garbage length values indicate TLS client configuration bug
2. Verify client crypter has `tls=true` flag set
3. Check that client sends packets with `UnencryptedFlag` set
4. Verify server processes TLS packets correctly

#### Scenario 4: TLS Handshake Succeeds but TACACS+ Fails
**Symptoms:**
```
Connected to server using TLS
execute pap authentication
{Status:AuthenStatusError Flags: ServerMsg:unencrypted flag not set Data:}
```

**Debug Steps:**
1. TLS layer is working correctly
2. TACACS+ protocol layer has issues
3. Check that client sends unencrypted packets within TLS tunnel
4. Verify server expects unencrypted packets for TLS connections

### 10. Useful OpenSSL Commands Reference

```bash
# Generate certificates with debugging
openssl req -new -key server.key -out server.csr -config server.conf -verbose

# View certificate details
openssl x509 -in server.crt -text -noout

# Test specific cipher suites
echo | openssl s_client -connect localhost:6653 -cipher ECDHE-RSA-AES256-GCM-SHA384

# Check certificate expiration
openssl x509 -in server.crt -noout -dates

# Verify certificate matches private key
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5
# The MD5 hashes should match
```

## Security Considerations

When deploying TACACS+ over TLS in production:

1. Use properly signed certificates from a trusted Certificate Authority
2. Ensure all certificates include proper SAN extensions
3. Implement certificate revocation checking
4. Regularly rotate certificates
5. Consider using mutual TLS authentication for stronger security
6. Follow your organization's PKI best practices
7. Never use `-tls-insecure-skip-verify` in production

## References

- [IETF draft-ietf-opsawg-tacacs-tls13-07](https://www.ietf.org/archive/id/draft-ietf-opsawg-tacacs-tls13-07.html)
- [TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 5280 - Certificate and Certificate Revocation List (CRL) Profile](https://datatracker.ietf.org/doc/html/rfc5280)
