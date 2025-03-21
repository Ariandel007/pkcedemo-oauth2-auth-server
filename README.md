
# OpenSSL to generate an RSA key pair (private and public keys) in PEM format

Run the following command to generate a private RSA key:
### Step 1: Generate a Private Key
Run the following command to generate a private RSA key:

```bash
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```

private_key.pem: The file containing your private key.
rsa_keygen_bits: Sets the size of the key (2048 is recommended for security).


### Step 2: Extract the Public Key
Run the following command to extract the public key from the private key:
```bash
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

public_key.pem: The file containing your public key.


### Step 3: Convert Keys to Base64
Just use the base64 part of both keys

### Step 4: Verify the Keys
To verify the private key:
```bash
openssl rsa -in private_key.pem -check
```
To verify the public key:
```bash
openssl rsa -pubin -in public_key.pem -text -noout
```
