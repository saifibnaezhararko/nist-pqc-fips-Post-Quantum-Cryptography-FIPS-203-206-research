# FIPS 203–206 Implementation Research Report

---

## Part 1: Comparison of Finalised NIST PQC Standards

NIST finalised four Post-Quantum Cryptography (PQC) standards in August 2024. They address two
cryptographic primitives: **Key Encapsulation Mechanisms (KEMs)** and **Digital Signatures**.

---

### ML-KEM — FIPS 203 (Key Encapsulation Mechanism)

**Mathematical basis:** Module Learning With Errors (M-LWE)
**Purpose:** Secure key exchange / key encapsulation

| Parameter Set | Public Key | Secret Key | Ciphertext | Shared Secret | NIST Security Level |
|---------------|-----------|-----------|-----------|---------------|---------------------|
| ML-KEM-512    | 800 B     | 1,632 B   | 768 B     | 32 B          | Level 1 (≈ AES-128) |
| ML-KEM-768    | 1,184 B   | 2,400 B   | 1,088 B   | 32 B          | Level 3 (≈ AES-192) |
| ML-KEM-1024   | 1,568 B   | 3,168 B   | 1,568 B   | 32 B          | Level 5 (≈ AES-256) |

**Notes:**
- Successor to CRYSTALS-Kyber (NIST Round 3 winner).
- Uses polynomial rings over Z_q with q = 3329.
- The shared secret is always 32 bytes regardless of parameter set.
- Designed for forward secrecy when used in ephemeral mode.

---

### ML-DSA — FIPS 204 (Digital Signature Algorithm)

**Mathematical basis:** Module Learning With Errors (M-LWE) + Module Short Integer Solution (M-SIS)
**Purpose:** Digital signatures

| Parameter Set | Public Key | Secret Key | Signature  | NIST Security Level |
|---------------|-----------|-----------|-----------|---------------------|
| ML-DSA-44     | 1,312 B   | 2,528 B   | 2,420 B   | Level 2             |
| ML-DSA-65     | 1,952 B   | 4,000 B   | 3,293 B   | Level 3             |
| ML-DSA-87     | 2,592 B   | 4,864 B   | 4,595 B   | Level 5             |

**Notes:**
- Successor to CRYSTALS-Dilithium.
- Deterministic signing by default; randomised signing is optional.
- Based on the Fiat-Shamir with Aborts paradigm.
- Signatures and keys are significantly larger than classical ECDSA equivalents.

---

### SLH-DSA — FIPS 205 (Stateless Hash-Based Digital Signature Algorithm)

**Mathematical basis:** Hash functions only (XMSS/WOTS+ trees, FORS)
**Purpose:** Digital signatures (conservative, hash-based)

| Parameter Set    | Public Key | Secret Key | Signature   | NIST Security Level |
|------------------|-----------|-----------|------------|---------------------|
| SLH-DSA-SHA2-128s | 32 B     | 64 B      | 7,856 B    | Level 1             |
| SLH-DSA-SHA2-128f | 32 B     | 64 B      | 17,088 B   | Level 1             |
| SLH-DSA-SHA2-192s | 48 B     | 96 B      | 16,224 B   | Level 3             |
| SLH-DSA-SHA2-192f | 48 B     | 96 B      | 35,664 B   | Level 3             |
| SLH-DSA-SHA2-256s | 64 B     | 128 B     | 29,792 B   | Level 5             |
| SLH-DSA-SHA2-256f | 64 B     | 128 B     | 49,856 B   | Level 5             |

*(SHAKE variants have identical sizes.)*
**Suffix `s` = small signatures (slower); `f` = fast signing (larger signatures)**

**Notes:**
- Successor to SPHINCS+.
- Security relies **only** on hash function security — no algebraic assumptions.
- Tiny public/private keys but very large signatures (trade-off).
- Stateless: no need to track how many signatures have been made (unlike XMSS).
- Best used where long-term trust in lattice mathematics is a concern.

---

### FN-DSA — FIPS 206 (Fast Fourier Lattice-Based Compact Signatures over NTRU)

**Mathematical basis:** NTRU lattices over cyclotomic rings
**Purpose:** Digital signatures (compact)

| Parameter Set | Public Key | Secret Key | Signature | NIST Security Level |
|---------------|-----------|-----------|----------|---------------------|
| FN-DSA-512    | 897 B     | 1,281 B   | ~666 B   | Level 1             |
| FN-DSA-1024   | 1,793 B   | 2,305 B   | ~1,280 B | Level 5             |

**Notes:**
- Successor to FALCON.
- Compact signatures — the smallest of all NIST PQC signature schemes.
- Uses Gaussian sampling over NTRU lattices (complex to implement side-channel safely).
- Signing requires a floating-point fast Fourier transform (FFT), making constant-time
  implementation challenging on hardware without FPUs.
- Recommended when bandwidth/signature size is the primary concern.

---

### NIST PQC Standards — Consolidated Size Comparison

```
SCHEME          | PURPOSE | PK (B)  | SK (B)  | CT/SIG (B) | Security
----------------|---------|---------|---------|------------|----------
ML-KEM-512      | KEM     | 800     | 1,632   | 768 (CT)   | L1
ML-KEM-768      | KEM     | 1,184   | 2,400   | 1,088 (CT) | L3
ML-KEM-1024     | KEM     | 1,568   | 3,168   | 1,568 (CT) | L5
ML-DSA-44       | SIG     | 1,312   | 2,528   | 2,420      | L2
ML-DSA-65       | SIG     | 1,952   | 4,000   | 3,293      | L3
ML-DSA-87       | SIG     | 2,592   | 4,864   | 4,595      | L5
SLH-DSA-128s    | SIG     | 32      | 64      | 7,856      | L1
SLH-DSA-256f    | SIG     | 64      | 128     | 49,856     | L5
FN-DSA-512      | SIG     | 897     | 1,281   | ~666       | L1
FN-DSA-1024     | SIG     | 1,793   | 2,305   | ~1,280     | L5
```

---

## Part 2: Classical vs PQC Algorithm Comparison

### RSA-2048 vs ML-KEM-768

| Property                | RSA-2048                  | ML-KEM-768 (FIPS 203)         |
|-------------------------|---------------------------|-------------------------------|
| **Purpose**             | Key exchange / encryption | Key encapsulation             |
| **Mathematical basis**  | Integer factorisation      | Module-LWE (lattice)          |
| **Public key size**     | 256 bytes                 | 1,184 bytes (~4.6× larger)    |
| **Private key size**    | 1,192 bytes (PKCS#8)      | 2,400 bytes (~2× larger)      |
| **Ciphertext / Output** | 256 bytes                 | 1,088 bytes (~4.2× larger)    |
| **Shared secret**       | Variable                  | 32 bytes (fixed)              |
| **Key generation time** | ~5–50 ms (slow)           | ~0.1–0.5 ms (fast)            |
| **Encap/Decrypt time**  | ~0.1–5 ms                 | ~0.1–0.5 ms                   |
| **Quantum security**    | Broken by Shor's Algorithm| Believed quantum-secure       |
| **Classical security**  | 112 bits (2048-bit)       | ~177 bits (ML-KEM-768)        |
| **Forward secrecy**     | Requires DHE mode         | Ephemeral by design           |
| **NIST standard**       | PKCS#1 (classical)        | FIPS 203 (PQC)                |
| **Standardisation**     | 1977 (RSA), RFC 8017      | 2024 (FIPS 203)               |

**Key Observations:**
- RSA-2048 is **broken by Shor's algorithm** running on a sufficiently powerful quantum computer.
  The algorithm runs in polynomial time O((log N)³), reducing the key-break cost from
  sub-exponential (classical) to polynomial (quantum).
- ML-KEM's key/ciphertext sizes are larger, but its operation speed is **faster** than RSA for
  equivalent security levels.
- ML-KEM provides a fixed 32-byte shared secret, making integration with symmetric ciphers simple.
- RSA key generation involves prime generation which is computationally expensive; ML-KEM keygen
  is based on polynomial sampling, making it much faster.

---

## Part 3: Alternative PQC Algorithm — BIKE (Bit Flipping Key Encapsulation)

### What is BIKE?

**BIKE** (Bit Flipping Key Encapsulation) is a code-based Key Encapsulation Mechanism that was
a NIST PQC Round 4 candidate. It did not make it into the final FIPS standards but remains under
active standardisation consideration (it is on the NIST "alternate" list).

**Mathematical basis:** Quasi-Cyclic Moderate Density Parity-Check (QC-MDPC) codes
**Security assumption:** Hardness of decoding random quasi-cyclic codes (related to NP-hard syndrome decoding)

### BIKE Parameter Sets and Sizes

| Parameter Set | Public Key  | Secret Key  | Ciphertext  | Shared Secret | Security Level |
|---------------|-------------|-------------|-------------|---------------|----------------|
| BIKE-L1       | 1,541 B     | 3,110 B     | 1,573 B     | 32 B          | Level 1        |
| BIKE-L3       | 3,083 B     | 5,788 B     | 3,115 B     | 32 B          | Level 3        |
| BIKE-L5       | 5,122 B     | 10,276 B    | 5,154 B     | 32 B          | Level 5        |

### BIKE vs ML-KEM-768 Comparison

| Property                | ML-KEM-768               | BIKE-L3                         |
|-------------------------|--------------------------|----------------------------------|
| **Mathematical basis**  | Lattice (M-LWE)          | Error-Correcting Codes (QC-MDPC)|
| **Public key**          | 1,184 B                  | 3,083 B (~2.6× larger)          |
| **Secret key**          | 2,400 B                  | 5,788 B (~2.4× larger)          |
| **Ciphertext**          | 1,088 B                  | 3,115 B (~2.9× larger)          |
| **Decapsulation failure**| Negligible (exact)       | ~10⁻⁷ (rare failure prob.)      |
| **Speed**               | Fast                     | Moderate (iterative decoding)    |
| **NIST status**         | Standardised (FIPS 203)  | Round 4 / Alternate candidate   |
| **Key assumption**      | Lattice hardness          | Code decoding hardness           |
| **Quantum security**    | Yes                      | Yes                              |
| **Diversity value**     | Same family as ML-DSA    | Completely different hardness    |

### Why BIKE is Interesting

1. **Algorithmic diversity:** BIKE is based on a completely different hard problem (coding theory)
   than the lattice-based FIPS standards. If a breakthrough attacks lattice problems, code-based
   schemes remain secure.

2. **Decoding Failure Rate:** BIKE has a non-zero (though very small, ~10⁻⁷) probability of
   decapsulation failure, which is a unique characteristic requiring careful protocol design.

3. **Smaller codebase:** The algorithm is conceptually simpler than lattice schemes in some
   respects, though QC-MDPC decoding is non-trivial to implement efficiently.

4. **Historical roots:** Code-based cryptography traces back to McEliece (1978), making it one
   of the oldest PQC proposals — predating lattice cryptography.

5. **NIST's recommendation:** NIST intends to potentially standardise BIKE after further analysis,
   particularly for applications that value cryptographic diversity over key size efficiency.

### Other Notable Non-FIPS PQC Algorithms

| Algorithm    | Type       | Basis                   | Status                    |
|--------------|------------|-------------------------|---------------------------|
| **BIKE**     | KEM        | QC-MDPC codes           | NIST Round 4 alternate    |
| **HQC**      | KEM        | Hamming Quasi-Cyclic    | NIST Round 4 alternate    |
| **Classic McEliece** | KEM | Goppa codes          | NIST Round 4 alternate    |
| **NTRU Prime** | KEM      | NTRU variant            | Considered, not selected  |
| **Rainbow**  | Signature  | Multivariate quadratic  | Broken (2022) — retired   |
| **GeMSS**    | Signature  | Multivariate + HFEv-    | Not selected              |

---

## Summary

| Standard   | FIPS | Type      | Best Size Trade-off            | Key Strength         |
|------------|------|-----------|-------------------------------|----------------------|
| ML-KEM     | 203  | KEM       | Balanced (medium keys/CT)     | Lattice (M-LWE)      |
| ML-DSA     | 204  | Signature | Balanced (medium keys/sig)    | Lattice (M-LWE+SIS)  |
| SLH-DSA    | 205  | Signature | Tiny keys, huge signatures    | Hash-only            |
| FN-DSA     | 206  | Signature | Smallest signatures           | NTRU lattice         |
| BIKE       | —    | KEM       | Larger keys, code-based       | QC-MDPC codes        |
| RSA-2048   | —    | KEM/Enc   | Smaller keys, quantum-broken  | Integer factorisation |
