# pkcs11engine
SSL mutual authentication with Smart Card
These codes show how to get a certificate and key from smart card.

How does SSL mutual authentication work ?
Customers may add secure socket layer (SSL) certificates to their websites to secure their information. 
A browser connecting to the secure server will use the SSL protocol to connect and verify the server’s certificate. 
However, customers can also use Mutual Authentication to have both the client and server use signed certificates to authenticate each other. 
With Mutual Authentication, both client and server will provide signed certificates for verification.


Client sends ClientHello message.
Server responds with ServerHello message included server's certificate.
Verifies server certificate by client (This step is not implemented on the client side).
Server requests client's certificate in CertificateRequest message, so that the connection can be mutually authenticated.
Server concludes its part of the negotiation with ServerHelloDone message.
Client responds with Certificate message, which contains the client's certificate.
Client sends session key information (encrypted with server's public key) in ClientKeyExchangemessage.
Client sends a CertificateVerify message to let the server know it owns the sent certificate.
Client sends ChangeCipherSpec message to activate the negotiated options for all future messages it will send.
Client sends Finished message to let the server check the newly activated options.
Server sends ChangeCipherSpec message to activate the negotiated options for all future messages it will send.
Server sends Finished message to let the client check the newly activated options.
How the Client and Server Accomplish Each of the Checks for Client Authentication
Digital Signature:  The client sends a "Certificate Verify" message that contains a digitally signed copy of the previous handshake message.  This message is signed using the client certificate's private key.  The server can validate the message digest of the digital signature by using the client's public key (which is found in the client certificate).  Once the digital signature is validated, the server knows that the public key belonging to the client matches the private key used to create the signature.
Certificate Chain:  The server maintains a list of trusted Client Authorities (CAs), and this list determines which certificates the server will accept.  The server will use the public key from the CA certificate (which it has in its list of trusted CAs) to validate the CA's digital signature on the certificate being presented.  If the message digest has changed or if the public key does not correspond to the CA's private key used to sign the certificate, the verification fails and the handshake terminates.
Expiration Date and Validity Period:  The server compares the current date to the validity period listed in the certificate.  If the expiration date has not passed and the current date is within the period, then this check succeeds.  If it is not, then the verification fails and the handshake terminates.
Certificate Revocation Status:  The server compares the client certificate to the list of revoked certificates on the system.  If the client certificate is on the list, the verification fails and the handshake terminates.
