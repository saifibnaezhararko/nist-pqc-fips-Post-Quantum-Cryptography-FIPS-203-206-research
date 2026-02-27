import os
import time
import hashlib
import hmac
import statistics

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from kyber_py.kyber import Kyber768


def hkdf_combine(secret1: bytes, secret2: bytes, info: bytes = b"hybrid-key-exchange") -> bytes:
    ikm = secret1 + secret2
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(ikm)


def bytes_to_hex_preview(b: bytes, n: int = 8) -> str:
    return b[:n].hex() + "..."


def classical_x25519_exchange() -> tuple[bytes, dict]:
    timings = {}

    t0 = time.perf_counter()
    alice_private = X25519PrivateKey.generate()
    alice_public  = alice_private.public_key()
    timings["keygen_ms"] = (time.perf_counter() - t0) * 1000

    bob_private = X25519PrivateKey.generate()
    bob_public  = bob_private.public_key()

    t0 = time.perf_counter()
    alice_shared = alice_private.exchange(bob_public)
    bob_shared   = bob_private.exchange(alice_public)
    timings["exchange_ms"] = (time.perf_counter() - t0) * 1000

    assert alice_shared == bob_shared, "X25519 shared secrets do not match!"

    timings["total_ms"] = timings["keygen_ms"] + timings["exchange_ms"]

    meta = {
        **timings,
        "alice_pub_size": 32,
        "alice_priv_size": 32,
        "shared_secret_size": 32,
    }
    return alice_shared, meta


def hybrid_key_exchange() -> tuple[bytes, dict]:
    timings = {}

    t0 = time.perf_counter()

    alice_x_priv   = X25519PrivateKey.generate()
    alice_x_pub    = alice_x_priv.public_key()

    alice_kem_pk, alice_kem_sk = Kyber768.keygen()

    timings["alice_keygen_ms"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    bob_x_priv = X25519PrivateKey.generate()
    bob_x_pub  = bob_x_priv.public_key()
    timings["bob_keygen_ms"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    bob_x_secret = bob_x_priv.exchange(alice_x_pub)
    timings["x25519_exchange_ms"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    bob_pqc_secret, ciphertext = Kyber768.encaps(alice_kem_pk)
    timings["kem_encaps_ms"] = (time.perf_counter() - t0) * 1000

    alice_x_secret = alice_x_priv.exchange(bob_x_pub)
    assert alice_x_secret == bob_x_secret, "X25519 secrets do not match!"

    t0 = time.perf_counter()
    alice_pqc_secret = Kyber768.decaps(alice_kem_sk, ciphertext)
    timings["kem_decaps_ms"] = (time.perf_counter() - t0) * 1000

    assert alice_pqc_secret == bob_pqc_secret, "ML-KEM secrets do not match!"

    t0 = time.perf_counter()
    alice_session_key = hkdf_combine(alice_x_secret, alice_pqc_secret)
    bob_session_key   = hkdf_combine(bob_x_secret,   bob_pqc_secret)
    timings["hkdf_ms"] = (time.perf_counter() - t0) * 1000

    assert alice_session_key == bob_session_key, "Session keys do not match!"

    timings["total_ms"] = sum(timings.values())

    x25519_pub_size   = 32
    kem_pk_size       = len(alice_kem_pk)
    kem_sk_size       = len(alice_kem_sk)
    ciphertext_size   = len(ciphertext)
    session_key_size  = len(alice_session_key)

    meta = {
        **timings,
        "x25519_pub_size": x25519_pub_size,
        "x25519_priv_size": 32,
        "kem_pk_size": kem_pk_size,
        "kem_sk_size": kem_sk_size,
        "kem_ciphertext_size": ciphertext_size,
        "session_key_size": session_key_size,
        "total_data_transmitted":
            x25519_pub_size + kem_pk_size +
            x25519_pub_size + ciphertext_size,
        "x_secret_preview": bytes_to_hex_preview(alice_x_secret),
        "pqc_secret_preview": bytes_to_hex_preview(alice_pqc_secret),
        "session_key_preview": bytes_to_hex_preview(alice_session_key),
    }
    return alice_session_key, meta


def benchmark(fn, iterations: int = 50) -> dict:
    times = []
    for _ in range(iterations):
        _, meta = fn()
        times.append(meta["total_ms"])

    return {
        "iterations": iterations,
        "min_ms":    round(min(times), 4),
        "max_ms":    round(max(times), 4),
        "mean_ms":   round(statistics.mean(times), 4),
        "median_ms": round(statistics.median(times), 4),
        "stdev_ms":  round(statistics.stdev(times), 4),
    }


def print_separator(char: str = "-", width: int = 70) -> None:
    print(char * width)


def print_section(title: str) -> None:
    print()
    print_separator("=")
    print(f"  {title}")
    print_separator("=")


def main() -> None:
    print_section("HYBRID KEY EXCHANGE: X25519 + ML-KEM-768")
    print("  Classical (X25519) + Post-Quantum (ML-KEM-768 / FIPS 203)")
    print("  Combined via HKDF-SHA256")

    print_section("1. SINGLE RUN - KEY SIZES AND SECRETS")

    classical_secret, cl_meta = classical_x25519_exchange()
    print("\n  [ Classical X25519 Only ]")
    print(f"    Public key size  : {cl_meta['alice_pub_size']} bytes")
    print(f"    Private key size : {cl_meta['alice_priv_size']} bytes")
    print(f"    Shared secret    : {cl_meta['shared_secret_size']} bytes")
    print(f"    Secret preview   : {bytes_to_hex_preview(classical_secret)}")
    print(f"    Time (keygen)    : {cl_meta['keygen_ms']:.4f} ms")
    print(f"    Time (exchange)  : {cl_meta['exchange_ms']:.4f} ms")
    print(f"    TOTAL            : {cl_meta['total_ms']:.4f} ms")

    hybrid_key, hy_meta = hybrid_key_exchange()
    print("\n  [ Hybrid X25519 + ML-KEM-768 ]")
    print(f"    X25519 public key size   : {hy_meta['x25519_pub_size']} bytes")
    print(f"    ML-KEM-768 public key    : {hy_meta['kem_pk_size']} bytes")
    print(f"    ML-KEM-768 secret key    : {hy_meta['kem_sk_size']} bytes")
    print(f"    ML-KEM-768 ciphertext    : {hy_meta['kem_ciphertext_size']} bytes")
    print(f"    Session key size         : {hy_meta['session_key_size']} bytes")
    print(f"    Total data on wire       : {hy_meta['total_data_transmitted']} bytes")
    print(f"    X25519 secret preview    : {hy_meta['x_secret_preview']}")
    print(f"    ML-KEM secret preview    : {hy_meta['pqc_secret_preview']}")
    print(f"    Combined session key     : {hy_meta['session_key_preview']}")
    print()
    print(f"    Time (Alice keygen)      : {hy_meta['alice_keygen_ms']:.4f} ms")
    print(f"    Time (Bob keygen)        : {hy_meta['bob_keygen_ms']:.4f} ms")
    print(f"    Time (X25519 exchange)   : {hy_meta['x25519_exchange_ms']:.4f} ms")
    print(f"    Time (ML-KEM encaps)     : {hy_meta['kem_encaps_ms']:.4f} ms")
    print(f"    Time (ML-KEM decaps)     : {hy_meta['kem_decaps_ms']:.4f} ms")
    print(f"    Time (HKDF combine)      : {hy_meta['hkdf_ms']:.4f} ms")
    print(f"    TOTAL                    : {hy_meta['total_ms']:.4f} ms")

    print_section("2. BANDWIDTH / WIRE-SIZE COMPARISON")
    print_separator()
    classical_wire = 32 + 32
    hybrid_wire    = hy_meta["total_data_transmitted"]

    print(f"  {'Scheme':<30} {'Data on wire (bytes)':>20}")
    print_separator()
    print(f"  {'Classical X25519':<30} {classical_wire:>20}")
    print(f"  {'Hybrid X25519+ML-KEM-768':<30} {hybrid_wire:>20}")
    print_separator()
    print(f"\n  Overhead factor : {hybrid_wire / classical_wire:.1f}x")
    print(f"  Extra bytes     : {hybrid_wire - classical_wire} bytes "
          f"({hybrid_wire - classical_wire} = ML-KEM PK {hy_meta['kem_pk_size']} + CT {hy_meta['kem_ciphertext_size']})")

    print_section("3. PERFORMANCE BENCHMARK")
    iterations = 30
    print(f"  Running {iterations} iterations each. Please wait...\n")

    print("  Benchmarking Classical X25519...")
    cl_bench = benchmark(classical_x25519_exchange, iterations)

    print("  Benchmarking Hybrid X25519 + ML-KEM-768...")
    hy_bench = benchmark(hybrid_key_exchange, iterations)

    print_separator()
    print(f"  {'Metric':<20} {'Classical X25519':>18} {'Hybrid':>18}")
    print_separator()
    for key in ("min_ms", "max_ms", "mean_ms", "median_ms", "stdev_ms"):
        label = key.replace("_ms", "").capitalize()
        print(f"  {label:<20} {cl_bench[key]:>15.4f} ms {hy_bench[key]:>15.4f} ms")
    print_separator()

    overhead_pct = ((hy_bench["median_ms"] - cl_bench["median_ms"])
                    / cl_bench["median_ms"] * 100)
    print(f"\n  Performance overhead of hybrid vs classical:")
    print(f"    Median  : {hy_bench['median_ms']:.4f} ms  vs  {cl_bench['median_ms']:.4f} ms")
    print(f"    Overhead: +{overhead_pct:.1f}% slower")
    print(f"\n  Note: kyber-py is a pure-Python reference implementation.")
    print(f"  In production (liboqs C library), ML-KEM-768 keygen ~= 0.05 ms,")
    print(f"  encaps ~= 0.06 ms, decaps ~= 0.07 ms -- total hybrid overhead < 0.5 ms.")

    print_section("4. SECURITY ANALYSIS")
    print("""
  HYBRID SECURITY GUARANTEE
  -------------------------
  The combined session key K = HKDF(x_secret || pqc_secret) is secure as long
  as AT LEAST ONE of the two components remains secure.

  Threat            | X25519        | ML-KEM-768     | Hybrid
  ------------------|---------------|----------------|----------
  Classical adv.    | SECURE        | SECURE         | SECURE
  Quantum adv.      | BROKEN        | SECURE         | SECURE
  PQC cryptanal.    | SECURE        | Potentially    | SECURE
  (future)          |               | vulnerable     |

  This is the rationale for the hybrid approach during the PQC transition
  period recommended by NIST, NSA, ENISA, and ETSI.

  ML-KEM-768 targets NIST Security Level 3, equivalent to AES-192.
  X25519 provides ~128 bits of classical security.
  Combined: 128-bit classical + 177-bit post-quantum protection.
    """)

    print_section("5. PROTOCOL MESSAGE FLOW")
    print("""
  Alice                                    Bob
  -----                                    ---
  Generate X25519 key pair
  Generate ML-KEM-768 key pair
                                           Generate X25519 key pair
  --> alice_x25519_pub (32 B)  ---------->
  --> alice_kem_pk (1184 B)    ---------->
                                           x_secret = DH(bob_priv, alice_x25519_pub)
                                           pqc_secret, ct = ML-KEM.Encaps(alice_kem_pk)
  <-- bob_x25519_pub (32 B)   <----------
  <-- kem_ciphertext (1088 B) <----------
  x_secret   = DH(alice_priv, bob_x25519_pub)
  pqc_secret = ML-KEM.Decaps(alice_kem_sk, ct)
  K = HKDF(x_secret || pqc_secret)        K = HKDF(x_secret || pqc_secret)
  ==============================================================
  Both parties now hold the same 32-byte session key K
    """)


if __name__ == "__main__":
    main()
