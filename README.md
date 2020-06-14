# RSA-Blind-Signature
Generate blind message, sign it and check the signature with RSA.

## Algorith explained:
- generate **hash** (SHA512) over initial file
- compute **k** (blind factor) as follows:<br> 
  <b>k = U1  XOR  U2   XOR ...XOR  Un</b>
  <br> Where:<br>  
    - U1 = SHA512 [ passphrase || nonce]
    - U2 = SHA512 [passphrase || U1]  
    ...
    - Un = SHA512 [passphrase || Un-1] where <b>n</b> and <b>passphrase</b> is given by the user
- blind the hash as follow:<br>
    **blind** = hash * k ^ e mod n where <b>n</b> and <b>e</b> represents the modulus and the public exponent of a RSA public key
- sign the blind messge:<br>
    **sgn** =  blind ^ d mod n where **d** private RSA key coresponding to the Public Key used before
- "unblind" the signed message:<br>
    **unblind** = sgn * k ^ -1 mod n where **k^-1** represents the invers of k mod n
- check the signature:<br>
    **extracted_hash** = unblind ^ e mod n where **e** the public exponent of RSA KEY pair<br>
    compare extracted_hash with a calculated hash of the file
    
