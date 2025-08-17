# Write a program to implement Diffie-Hellman Key Exchange.

# Diffie-Hellman Key Exchange Implementation

# Step 1: Publicly known values
P = 23    # a prime number
G = 5     # a primitive root modulo P

print("Publicly Shared Variables:")
print("  Prime (P):", P)
print("  Base (G):", G)

# Step 2: Alice chooses a private key
a = 6   # Alice's private key (kept secret)
print("\nAlice's Private Key (a):", a)

# Step 3: Bob chooses a private key
b = 15  # Bob's private key (kept secret)
print("Bob's Private Key (b):", b)

# Step 4: Compute public keys
# A = G^a mod P
A = pow(G, a, P)
# B = G^b mod P
B = pow(G, b, P)

print("\nPublic Keys Exchanged:")
print("  Alice sends A:", A)
print("  Bob sends B:", B)

# Step 5: Each computes the shared secret
# Alice computes s = B^a mod P
alice_secret = pow(B, a, P)
# Bob computes s = A^b mod P
bob_secret = pow(A, b, P)

print("\nShared Secret Computed:")
print("  Alice's Secret:", alice_secret)
print("  Bob's Secret:  ", bob_secret)

# Check if both secrets match
if alice_secret == bob_secret:
    print("\n✅ Key Exchange Successful! Shared secret is:", alice_secret)
else:
    print("\n❌ Key Exchange Failed!")

