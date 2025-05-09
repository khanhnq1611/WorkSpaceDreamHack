# RSA Encryption Example with small primes
p = 13
q = 31
n = p * q             # n = 403
phi_n = (p - 1) * (q - 1)  # phi(n) = 360

e = 7  # public exponent, chosen such that gcd(e, phi_n) = 1

# Message to encrypt
M = 350

# Encryption: C = M^e mod n
C = pow(M, e, n)

print("Public key (e, n):", (e, n))
print("Plaintext M:", M)
print("Ciphertext C:", C)
