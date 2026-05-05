# MATH 4175 - Project 5: AES-128 First Round Encryption

**Group Members:** Luke Freeman, Yoshwan Pathipati, Diego Penadillo, Hiren Sai Vellanki

---

## 1. Input

**Plaintext message:** "I need an A+ plz"

**Plaintext (hex):** `49 20 6E 65 65 64 20 61 6E 20 41 2B 20 70 6C 7A`

**AES Key (hex):** `45 6E 63 72 79 70 74 20 6D 79 20 6D 61 72 6B 73`

---

## 2. Round Key K0

The initial round key K0 is the AES key bytes arranged column-wise into a 4x4 state matrix.

### K0 Matrix

```
[45 79 6D 61]
[6E 70 79 72]
[63 74 20 6B]
[72 20 6D 73]
```

---

## 3. Round Key K1 (Key Schedule)

The AES-128 key schedule generates round keys by expanding the original 16-byte key into 44 words (4 bytes each).

### Key Schedule Steps for Round 1

**Initial words from the key:**
- W0 = `[45 6E 63 72]`
- W1 = `[79 70 74 20]`
- W2 = `[6D 79 20 6D]`
- W3 = `[61 72 6B 73]`

**Computing W4:**
1. RotWord(W3) = `[72 6B 73 61]`
2. SubWord(RotWord(W3)) = `[40 7F 8F EF]`
3. XOR with Rcon[0] = `[01 00 00 00]`
4. g(W3) = `[41 7F 8F EF]`
5. W4 = W0 XOR g(W3) = `[04 11 EC 9D]`

**W5 = W1 XOR W4** = `[7D 61 98 BD]`

**W6 = W2 XOR W5** = `[10 18 B8 D0]`

**W7 = W3 XOR W6** = `[71 6A D3 A3]`

### K1 Matrix

```
[04 7D 10 71]
[11 61 18 6A]
[EC 98 B8 D3]
[9D BD D0 A3]
```

---

## 4. First Round Encryption

### Initial State

The plaintext bytes are arranged column-wise into the 4x4 state matrix:

```
[49 65 6E 20]
[20 64 20 70]
[6E 20 41 6C]
[65 61 2B 7A]
```

### (a) After AddRoundKey with K0

XOR each byte of the initial state with the corresponding byte of K0.

```
[0C 1C 03 41]
[4E 14 59 02]
[0D 54 61 07]
[17 41 46 09]
```

### (b) After SubBytes

Apply the AES S-Box substitution to every byte in the state. Each byte is replaced by its value in the S-Box lookup table.

```
[FE 9C 7B 83]
[2F FA CB 77]
[D7 20 EF C5]
[F0 83 5A 01]
```

### (c) After ShiftRows

Cyclically shift each row to the left:
- Row 0: no shift
- Row 1: shift left by 1
- Row 2: shift left by 2
- Row 3: shift left by 3

```
[FE 9C 7B 83]
[FA CB 77 2F]
[EF C5 D7 20]
[01 F0 83 5A]
```

### (d) After MixColumns

Apply the MixColumns transformation using GF(2^8) multiplication with irreducible polynomial x^8 + x^4 + x^3 + x + 1. Each column is multiplied by the fixed matrix:

```
[02 03 01 01]
[01 02 03 01]
[01 01 02 03]
[03 01 01 02]
```

```
[1C 50 3B 16]
[3A B5 74 E7]
[C2 CD 27 02]
[0E 4A 30 25]
```

### (e) After AddRoundKey with K1

XOR each byte of the state with the corresponding byte of K1. This is the final state after the first AES round.

```
[18 2D 2B 67]
[2B D4 6C 8D]
[2E 55 9F D1]
[93 F7 E0 86]
```

---

## 5. Explanation of Each Step

1. **AddRoundKey (K0):** The plaintext state is XORed with the initial round key K0. This ensures the encryption is key-dependent from the very first operation.

2. **SubBytes:** A non-linear byte substitution using the AES S-Box. This provides confusion, making the relationship between the key and ciphertext complex.

3. **ShiftRows:** Each row is cyclically shifted left by a different amount. This provides diffusion by permuting bytes across columns.

4. **MixColumns:** Each column is multiplied by a fixed polynomial matrix over GF(2^8). This provides further diffusion by mixing bytes within each column.

5. **AddRoundKey (K1):** The state is XORed with the first expanded round key K1. This ensures the result is key-dependent before proceeding to subsequent rounds.

---

*Source code: project5_aes_first_round.py*
*Generated programmatically to ensure accuracy.*
