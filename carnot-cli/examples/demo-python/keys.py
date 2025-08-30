from cryptography.hazmat.primitives.asymmetric import rsa
k=rsa.generate_private_key(public_exponent=3,key_size=1024)
