# Blindspot - SASCTF 2025

**Category:** Cryptography
**Challenge Author:** (If known, or N/A)
**Source:** SASCTF 2025 (`tcp.sasc.tf:12610`)

## Challenge Description

> Every security system has its blindspot - that one vulnerable angle that remains hidden from view. Today, your mission is to find one.
> `nc tcp.sasc.tf 12610`

This challenge involves a server implementing a Schnorr-like blind signature scheme. Participants are expected to find and exploit a vulnerability in its cryptographic protocol to retrieve the flag.

## Vulnerability: Nonce Reuse

The core vulnerability in this challenge is **nonce reuse** in the server's Schnorr-like signature scheme.

The server generates a cryptographic nonce `k` once per client connection (session). This same nonce `k` is then used for all subsequent signature `CHALLENGE` requests within that same session.

If an attacker requests the server to sign two different challenges, `c_1` and `c_2`, using the same nonce `k` and the server's private key `d`, the server will produce:

1.  `s_1 = (k + c_1 \cdot d) \pmod p`
2.  `s_2 = (k + c_2 \cdot d) \pmod p`

By subtracting these two equations, `k` is eliminated:
`s_1 - s_2 = (c_1 - c_2) \cdot d \pmod p`

If `c_1 \neq c_2`, the server's private key `d` can be calculated:
`d = (s_1 - s_2) \cdot (c_1 - c_2)^{-1} \pmod p`

Once `d` is known, signatures can be forged for arbitrary messages. The goal is to have more verified messages than actual signing operations performed with the server (`len(verified_messages) > counter_sign`).

## Exploitation Steps

1.  **Connect & Reset:** Establish a connection and reset the server state.
2.  **Get Public Key:** Retrieve the server's public key `Q`.
3.  **First Challenge:** Initiate a signing session, send a crafted challenge `c_server_1`, and receive `s_server_1`. This uses the session's nonce `k_serv`.
4.  **Second Challenge:** On the *same connection* (reusing `k_serv`), send a different crafted challenge `c_server_2` and receive `s_server_2`.
5.  **Recover Private Key `d`:** Use `s_server_1`, `s_server_2`, `c_server_1`, and `c_server_2` to calculate `d`. Verify `d` using `Q`.
6.  **Forge Signatures:** With `d`, forge at least three signatures for new, distinct messages.
7.  **Verify Forged Signatures:** Send these forged signatures to the server's `VERIFY` endpoint. This increases `len(verified_messages)` without increasing `counter_sign` (which was incremented only during the two initial `CHALLENGE` calls).
8.  **Get Flag:** Once `len(verified_messages) > counter_sign`, the server sends the flag.

## Solver Script (`solver.py`)

A Python script named `solver.py` is provided in this repository to automate the exploitation process. Please refer to the script itself for the full implementation details.

### Dependencies

The solver script requires the `ecdsa` Python library:

```bash
pip install ecdsa
