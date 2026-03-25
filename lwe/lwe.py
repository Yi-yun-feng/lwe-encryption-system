# -*- coding: utf-8 -*-
import numpy as np
import random

class LWE:
    def __init__(self, n=64, q=997, sigma=3.0):
        self.n = n
        self.q = q
        self.sigma = sigma
    
    def _sample_error(self):
        return int(round(random.gauss(0, self.sigma))) % self.q
    
    def key_gen(self):
        s = np.random.randint(0, 2, self.n)
        A = np.random.randint(0, self.q, (self.n, self.n))
        e = np.array([self._sample_error() for _ in range(self.n)])
        b = (A @ s + e) % self.q
        return (A, b), s
    
    def encrypt(self, public_key, message):
        A, b = public_key
        r = np.random.randint(0, 2, self.n)
        u = (A.T @ r) % self.q
        v = (b @ r + message * (self.q // 2)) % self.q
        return (u, v)
    
    def decrypt(self, secret_key, ciphertext):
        s = secret_key
        u, v = ciphertext
        val = (v - s @ u) % self.q
        if val > self.q // 4 and val < 3 * self.q // 4:
            return 1
        else:
            return 0

if __name__ == "__main__":
    lwe = LWE()
    public_key, secret_key = lwe.key_gen()
    print("Key generated")
    message = 1
    ciphertext = lwe.encrypt(public_key, message)
    decrypted = lwe.decrypt(secret_key, ciphertext)
    print(f"Encrypt:{message} -> Decrypt:{decrypted}")
    if message == decrypted:
        print("LWE OK!")