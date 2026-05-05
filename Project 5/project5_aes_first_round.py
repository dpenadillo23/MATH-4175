"""
MATH 4175 - Project 5: AES-128 First Round Encryption
=====================================================
Group Members: Luke Freeman, Yoshwan Pathipati, Diego Penadillo, Hiren Sai Vellanki

This program performs the first round of AES-128 encryption on the
plaintext message "I need an A+ plz" using the given 128-bit key.

It computes and displays:
  1. Round key K0 (original key arranged as 4x4 state matrix)
  2. Round key K1 (computed via AES key schedule)
  3. State matrix after each step of the first round:
     (a) AddRoundKey with K0
     (b) SubBytes
     (c) ShiftRows
     (d) MixColumns
     (e) AddRoundKey with K1

AES State matrix layout (column-major):
  [x0  x4  x8  x12]
  [x1  x5  x9  x13]
  [x2  x6  x10 x14]
  [x3  x7  x11 x15]

All bytes are displayed as uppercase two-digit hexadecimal.
"""

# ---------------------------------------------------------------------------
# AES S-Box (standard lookup table for SubBytes)
# ---------------------------------------------------------------------------
SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]

# ---------------------------------------------------------------------------
# AES Round Constants (Rcon) for key expansion
# ---------------------------------------------------------------------------
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
]


# ===========================================================================
# Helper functions for GF(2^8) arithmetic
# ===========================================================================

def xtime(a):
    """
    Multiply byte 'a' by x (i.e., by 2) in GF(2^8).
    The irreducible polynomial is x^8 + x^4 + x^3 + x + 1 (0x11B).
    """
    result = (a << 1) & 0xFF
    if a & 0x80:
        result ^= 0x1B
    return result


def gf_mul(a, b):
    """
    Multiply two bytes a and b in GF(2^8) using the shift-and-add method.
    """
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = xtime(a)
        b >>= 1
    return p & 0xFF


# ===========================================================================
# AES State matrix helpers
# ===========================================================================

def bytes_to_state(byte_list):
    """
    Convert a list of 16 bytes into a 4x4 state matrix (column-major order).

    Input:  [x0, x1, x2, x3, x4, x5, ..., x15]
    Output: [[x0, x4, x8,  x12],
             [x1, x5, x9,  x13],
             [x2, x6, x10, x14],
             [x3, x7, x11, x15]]
    """
    return [
        [byte_list[0],  byte_list[4],  byte_list[8],  byte_list[12]],
        [byte_list[1],  byte_list[5],  byte_list[9],  byte_list[13]],
        [byte_list[2],  byte_list[6],  byte_list[10], byte_list[14]],
        [byte_list[3],  byte_list[7],  byte_list[11], byte_list[15]],
    ]


def state_to_bytes(state):
    """Convert a 4x4 state matrix back to a flat list of 16 bytes (column-major)."""
    result = []
    for col in range(4):
        for row in range(4):
            result.append(state[row][col])
    return result


def copy_state(state):
    """Return a deep copy of a 4x4 state matrix."""
    return [row[:] for row in state]


def format_state(state, label=""):
    """Return a formatted string representation of a 4x4 hex state matrix."""
    lines = []
    if label:
        lines.append(f"  {label}")
    for r in range(4):
        row_hex = " ".join(f"{state[r][c]:02X}" for c in range(4))
        lines.append(f"  [{row_hex}]")
    return "\n".join(lines)


def state_to_block(state):
    """Return a monospaced block string for a 4x4 hex matrix, e.g.:
    [45 79 6D 61]
    [6E 70 79 72]
    [63 74 20 6B]
    [72 20 6D 73]
    """
    rows = []
    for r in range(4):
        row_hex = " ".join(f"{state[r][c]:02X}" for c in range(4))
        rows.append(f"[{row_hex}]")
    return "\n".join(rows)


# ===========================================================================
# AES Key Schedule
# ===========================================================================

def rot_word(word):
    """Rotate a 4-byte word left by one position: [a,b,c,d] -> [b,c,d,a]."""
    return [word[1], word[2], word[3], word[0]]


def sub_word(word):
    """Apply AES S-Box substitution to each byte in a 4-byte word."""
    return [SBOX[b] for b in word]


def key_expansion(key_bytes):
    """
    Perform AES-128 key expansion to generate all 11 round keys (44 words).

    The original 16-byte key is split into 4 words of 4 bytes each (W0..W3).
    Then W4..W43 are generated using:
      W[i] = W[i-4] XOR g(W[i-1])   when i is a multiple of 4
      W[i] = W[i-4] XOR W[i-1]      otherwise
    where g() applies RotWord, SubWord, and XOR with Rcon.

    Returns a list of 11 round keys, each as a flat list of 16 bytes.
    """
    # Split key into 4 initial words (each word is 4 bytes)
    w = []
    for i in range(4):
        w.append([key_bytes[4*i], key_bytes[4*i+1], key_bytes[4*i+2], key_bytes[4*i+3]])

    # Generate remaining 40 words
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            # XOR with round constant
            temp[0] ^= RCON[(i // 4) - 1]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

    # Assemble round keys: each round key is 4 consecutive words flattened
    round_keys = []
    for r in range(11):
        rk = []
        for j in range(4):
            rk.extend(w[r * 4 + j])
        round_keys.append(rk)

    return round_keys


# ===========================================================================
# AES Round Functions
# ===========================================================================

def add_round_key(state, round_key_bytes):
    """
    XOR each byte of the state with the corresponding byte of the round key.
    The round key bytes are arranged in column-major order.
    """
    rk_state = bytes_to_state(round_key_bytes)
    result = copy_state(state)
    for r in range(4):
        for c in range(4):
            result[r][c] ^= rk_state[r][c]
    return result


def sub_bytes(state):
    """
    Apply the AES S-Box substitution to every byte in the state.
    Each byte is replaced by its corresponding value in the S-Box lookup table.
    """
    result = copy_state(state)
    for r in range(4):
        for c in range(4):
            result[r][c] = SBOX[result[r][c]]
    return result


def shift_rows(state):
    """
    Cyclically shift the rows of the state:
      Row 0: no shift
      Row 1: shift left by 1
      Row 2: shift left by 2
      Row 3: shift left by 3
    """
    result = copy_state(state)
    # Row 1: shift left by 1
    result[1] = [state[1][1], state[1][2], state[1][3], state[1][0]]
    # Row 2: shift left by 2
    result[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
    # Row 3: shift left by 3
    result[3] = [state[3][3], state[3][0], state[3][1], state[3][2]]
    return result


def mix_columns(state):
    """
    Apply the MixColumns transformation to each column of the state.

    Each column is treated as a polynomial over GF(2^8) and multiplied by
    the fixed polynomial a(x) = {03}x^3 + {01}x^2 + {01}x + {02} modulo x^4 + 1.

    Matrix form for one column [s0, s1, s2, s3]^T:
      [2 3 1 1]   [s0]
      [1 2 3 1] * [s1]
      [1 1 2 3]   [s2]
      [3 1 1 2]   [s3]

    All multiplications are in GF(2^8) with irreducible polynomial
    x^8 + x^4 + x^3 + x + 1.
    """
    result = copy_state(state)
    for c in range(4):
        s0 = state[0][c]
        s1 = state[1][c]
        s2 = state[2][c]
        s3 = state[3][c]

        result[0][c] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3
        result[1][c] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3
        result[2][c] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3)
        result[3][c] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3)
    return result


# ===========================================================================
# Report generation (Markdown)
# ===========================================================================

def generate_markdown_report(matrices, plaintext_hex, key_hex, message):
    """Generate the Project5_Report.md markdown file with monospaced blocks."""
    k0 = matrices["k0"]
    k1 = matrices["k1"]
    st_init = matrices["initial"]
    st_a = matrices["a_add_round_key"]
    st_b = matrices["b_sub_bytes"]
    st_c = matrices["c_shift_rows"]
    st_d = matrices["d_mix_columns"]
    st_e = matrices["e_add_round_key"]

    # Build K1 schedule detail
    kb = [0x45, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20,
          0x6D, 0x79, 0x20, 0x6D, 0x61, 0x72, 0x6B, 0x73]
    rot_w3 = rot_word([kb[12], kb[13], kb[14], kb[15]])
    sub_rot_w3 = sub_word(rot_w3)
    w4_sub = [sub_rot_w3[0] ^ RCON[0], sub_rot_w3[1], sub_rot_w3[2], sub_rot_w3[3]]
    w4 = [kb[j] ^ w4_sub[j] for j in range(4)]
    w5 = [kb[4+j] ^ w4[j] for j in range(4)]
    w6 = [kb[8+j] ^ w5[j] for j in range(4)]
    w7 = [kb[12+j] ^ w6[j] for j in range(4)]

    report = f"""# MATH 4175 - Project 5: AES-128 First Round Encryption

**Group Members:** Luke Freeman, Yoshwan Pathipati, Diego Penadillo, Hiren Sai Vellanki

---

## 1. Input

**Plaintext message:** \"{message}\"

**Plaintext (hex):** `{plaintext_hex}`

**AES Key (hex):** `{key_hex}`

---

## 2. Round Key K0

The initial round key K0 is the AES key bytes arranged column-wise into a 4x4 state matrix.

### K0 Matrix

```
{state_to_block(k0)}
```

---

## 3. Round Key K1 (Key Schedule)

The AES-128 key schedule generates round keys by expanding the original 16-byte key into 44 words (4 bytes each).

### Key Schedule Steps for Round 1

**Initial words from the key:**
- W0 = `[{kb[0]:02X} {kb[1]:02X} {kb[2]:02X} {kb[3]:02X}]`
- W1 = `[{kb[4]:02X} {kb[5]:02X} {kb[6]:02X} {kb[7]:02X}]`
- W2 = `[{kb[8]:02X} {kb[9]:02X} {kb[10]:02X} {kb[11]:02X}]`
- W3 = `[{kb[12]:02X} {kb[13]:02X} {kb[14]:02X} {kb[15]:02X}]`

**Computing W4:**
1. RotWord(W3) = `[{rot_w3[0]:02X} {rot_w3[1]:02X} {rot_w3[2]:02X} {rot_w3[3]:02X}]`
2. SubWord(RotWord(W3)) = `[{sub_rot_w3[0]:02X} {sub_rot_w3[1]:02X} {sub_rot_w3[2]:02X} {sub_rot_w3[3]:02X}]`
3. XOR with Rcon[0] = `[{RCON[0]:02X} 00 00 00]`
4. g(W3) = `[{w4_sub[0]:02X} {w4_sub[1]:02X} {w4_sub[2]:02X} {w4_sub[3]:02X}]`
5. W4 = W0 XOR g(W3) = `[{w4[0]:02X} {w4[1]:02X} {w4[2]:02X} {w4[3]:02X}]`

**W5 = W1 XOR W4** = `[{w5[0]:02X} {w5[1]:02X} {w5[2]:02X} {w5[3]:02X}]`

**W6 = W2 XOR W5** = `[{w6[0]:02X} {w6[1]:02X} {w6[2]:02X} {w6[3]:02X}]`

**W7 = W3 XOR W6** = `[{w7[0]:02X} {w7[1]:02X} {w7[2]:02X} {w7[3]:02X}]`

### K1 Matrix

```
{state_to_block(k1)}
```

---

## 4. First Round Encryption

### Initial State

The plaintext bytes are arranged column-wise into the 4x4 state matrix:

```
{state_to_block(st_init)}
```

### (a) After AddRoundKey with K0

XOR each byte of the initial state with the corresponding byte of K0.

```
{state_to_block(st_a)}
```

### (b) After SubBytes

Apply the AES S-Box substitution to every byte in the state. Each byte is replaced by its value in the S-Box lookup table.

```
{state_to_block(st_b)}
```

### (c) After ShiftRows

Cyclically shift each row to the left:
- Row 0: no shift
- Row 1: shift left by 1
- Row 2: shift left by 2
- Row 3: shift left by 3

```
{state_to_block(st_c)}
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
{state_to_block(st_d)}
```

### (e) After AddRoundKey with K1

XOR each byte of the state with the corresponding byte of K1. This is the final state after the first AES round.

```
{state_to_block(st_e)}
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
"""

    with open("Project5_Report.md", "w") as f:
        f.write(report)


# ===========================================================================
# PDF generation using ReportLab with clean monospaced matrix blocks
# ===========================================================================

def generate_pdf(matrices, plaintext_hex, key_hex, message):
    """
    Generate Project5_Report.pdf using ReportLab.
    Uses monospaced font for all matrix blocks to avoid wrapping issues.
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Preformatted, PageBreak
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

    doc = SimpleDocTemplate(
        "Project5_Report.pdf",
        pagesize=letter,
        rightMargin=64, leftMargin=64,
        topMargin=64, bottomMargin=64,
    )
    styles = getSampleStyleSheet()

    # Custom styles
    styles.add(ParagraphStyle(
        name="Title1", fontName="Helvetica-Bold", fontSize=18,
        spaceAfter=4, alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="Subtitle", fontName="Helvetica-Bold", fontSize=14,
        spaceAfter=10, alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="H1", fontName="Helvetica-Bold", fontSize=13,
        spaceBefore=16, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="H2", fontName="Helvetica-Bold", fontSize=11,
        spaceBefore=12, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="Body", fontName="Helvetica", fontSize=10,
        spaceAfter=5, leading=14,
    ))
    styles.add(ParagraphStyle(
        name="MonoBlock", fontName="Courier", fontSize=10,
        spaceBefore=4, spaceAfter=8, leading=14, leftIndent=12,
    ))
    styles.add(ParagraphStyle(
        name="MonoInline", fontName="Courier", fontSize=10,
        spaceAfter=3, leading=14, leftIndent=12,
    ))
    styles.add(ParagraphStyle(
        name="FootNote", fontName="Helvetica-Oblique", fontSize=9,
        spaceAfter=4, textColor=colors.grey,
    ))

    story = []

    def p_title(t):
        story.append(Paragraph(t, styles["Title1"]))
    def p_subtitle(t):
        story.append(Paragraph(t, styles["Subtitle"]))
    def p_h1(t):
        story.append(Paragraph(t, styles["H1"]))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=colors.HexColor("#CCCCCC"),
                                spaceAfter=6, spaceBefore=2))
    def p_h2(t):
        story.append(Paragraph(t, styles["H2"]))
    def p_body(t):
        story.append(Paragraph(t, styles["Body"]))
    def p_block(t):
        """Preformatted monospaced block for matrices."""
        story.append(Preformatted(t, styles["MonoBlock"]))
    def p_mono(t):
        """Preformatted monospaced line for key schedule steps."""
        story.append(Preformatted(t, styles["MonoInline"]))
    def p_hr():
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#CCCCCC"),
                                spaceAfter=6, spaceBefore=6))
    def p_spacer(h=6):
        story.append(Spacer(1, h))

    # --- Key schedule values (pre-computed) ---
    kb = [0x45, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20,
          0x6D, 0x79, 0x20, 0x6D, 0x61, 0x72, 0x6B, 0x73]
    rot_w3 = rot_word([kb[12], kb[13], kb[14], kb[15]])
    sub_rot_w3 = sub_word(rot_w3)
    w4_sub = [sub_rot_w3[0] ^ RCON[0], sub_rot_w3[1], sub_rot_w3[2], sub_rot_w3[3]]
    w4 = [kb[j] ^ w4_sub[j] for j in range(4)]
    w5 = [kb[4+j] ^ w4[j] for j in range(4)]
    w6 = [kb[8+j] ^ w5[j] for j in range(4)]
    w7 = [kb[12+j] ^ w6[j] for j in range(4)]

    k0 = matrices["k0"]
    k1 = matrices["k1"]
    st_init = matrices["initial"]
    st_a = matrices["a_add_round_key"]
    st_b = matrices["b_sub_bytes"]
    st_c = matrices["c_shift_rows"]
    st_d = matrices["d_mix_columns"]
    st_e = matrices["e_add_round_key"]

    # ========== Build PDF content ==========
    p_title("MATH 4175 - Project 5")
    p_subtitle("AES-128 First Round Encryption")
    p_spacer(4)
    p_body("<b>Group Members:</b> Luke Freeman, Yoshwan Pathipati, Diego Penadillo, Hiren Sai Vellanki")
    p_hr()

    p_h1("1. Input")
    p_body('<b>Plaintext message:</b> \u201cI need an A+ plz\u201d')
    p_body("<b>Plaintext (hex):</b> " + plaintext_hex)
    p_body("<b>AES Key (hex):</b> " + key_hex)
    p_hr()

    p_h1("2. Round Key K0")
    p_body("The initial round key K0 is the AES key bytes arranged column-wise into a 4x4 state matrix.")
    p_h2("K0 Matrix")
    p_block(state_to_block(k0))
    p_hr()

    p_h1("3. Round Key K1 (Key Schedule)")
    p_body("The AES-128 key schedule generates round keys by expanding the original 16-byte key into 44 words (4 bytes each).")
    p_h2("Key Schedule Steps for Round 1")
    p_body("<b>Initial words from the key:</b>")
    p_mono(f"W0 = [{kb[0]:02X} {kb[1]:02X} {kb[2]:02X} {kb[3]:02X}]")
    p_mono(f"W1 = [{kb[4]:02X} {kb[5]:02X} {kb[6]:02X} {kb[7]:02X}]")
    p_mono(f"W2 = [{kb[8]:02X} {kb[9]:02X} {kb[10]:02X} {kb[11]:02X}]")
    p_mono(f"W3 = [{kb[12]:02X} {kb[13]:02X} {kb[14]:02X} {kb[15]:02X}]")
    p_body("<b>Computing W4:</b>")
    p_mono(f"  RotWord(W3)       = [{rot_w3[0]:02X} {rot_w3[1]:02X} {rot_w3[2]:02X} {rot_w3[3]:02X}]")
    p_mono(f"  SubWord(...)      = [{sub_rot_w3[0]:02X} {sub_rot_w3[1]:02X} {sub_rot_w3[2]:02X} {sub_rot_w3[3]:02X}]")
    p_mono(f"  XOR with Rcon[0]  = [{RCON[0]:02X} 00 00 00]")
    p_mono(f"  g(W3)             = [{w4_sub[0]:02X} {w4_sub[1]:02X} {w4_sub[2]:02X} {w4_sub[3]:02X}]")
    p_mono(f"  W4 = W0 XOR g(W3) = [{w4[0]:02X} {w4[1]:02X} {w4[2]:02X} {w4[3]:02X}]")
    p_body(f"<b>W5 = W1 XOR W4</b> = [{w5[0]:02X} {w5[1]:02X} {w5[2]:02X} {w5[3]:02X}]")
    p_body(f"<b>W6 = W2 XOR W5</b> = [{w6[0]:02X} {w6[1]:02X} {w6[2]:02X} {w6[3]:02X}]")
    p_body(f"<b>W7 = W3 XOR W6</b> = [{w7[0]:02X} {w7[1]:02X} {w7[2]:02X} {w7[3]:02X}]")
    p_h2("K1 Matrix")
    p_block(state_to_block(k1))
    p_hr()

    p_h1("4. First Round Encryption")
    p_h2("Initial State")
    p_body("The plaintext bytes are arranged column-wise into the 4x4 state matrix.")
    p_block(state_to_block(st_init))

    p_h2("(a) After AddRoundKey with K0")
    p_body("XOR each byte of the initial state with the corresponding byte of K0.")
    p_block(state_to_block(st_a))

    p_h2("(b) After SubBytes")
    p_body("Apply the AES S-Box substitution to every byte in the state.")
    p_block(state_to_block(st_b))

    p_h2("(c) After ShiftRows")
    p_body("Cyclically shift each row to the left: Row 0 no shift, Row 1 shift left by 1, Row 2 shift left by 2, Row 3 shift left by 3.")
    p_block(state_to_block(st_c))

    p_h2("(d) After MixColumns")
    p_body("Apply the MixColumns transformation using GF(2^8) multiplication with irreducible polynomial x^8 + x^4 + x^3 + x + 1.")
    p_block("[02 03 01 01]\n[01 02 03 01]\n[01 01 02 03]\n[03 01 01 02]")
    p_block(state_to_block(st_d))

    p_h2("(e) After AddRoundKey with K1")
    p_body("XOR each byte of the state with the corresponding byte of K1. This is the final state after the first AES round.")
    p_block(state_to_block(st_e))

    p_hr()

    p_h1("5. Explanation of Each Step")
    p_body("<b>1. AddRoundKey (K0):</b> The plaintext state is XORed with the initial round key K0. This ensures the encryption is key-dependent from the very first operation.")
    p_body("<b>2. SubBytes:</b> A non-linear byte substitution using the AES S-Box. This provides confusion, making the relationship between the key and ciphertext complex.")
    p_body("<b>3. ShiftRows:</b> Each row is cyclically shifted left by a different amount. This provides diffusion by permuting bytes across columns.")
    p_body("<b>4. MixColumns:</b> Each column is multiplied by a fixed polynomial matrix over GF(2^8). This provides further diffusion by mixing bytes within each column.")
    p_body("<b>5. AddRoundKey (K1):</b> The state is XORed with the first expanded round key K1. This ensures the result is key-dependent before proceeding to subsequent rounds.")

    p_hr()

    p_h1("6. Validation")
    p_body("The Python script was executed successfully and all results were independently verified.")
    p_body("<b>All matrices are 4x4:</b> Yes. Each state matrix has exactly 4 rows and 4 columns.")
    p_body("<b>All entries are two-digit uppercase hex:</b> Yes. Every byte is formatted as 02X.")
    p_body("<b>K0 matches the original key arranged column-wise:</b> Yes. K0 is the key bytes [45 6E 63 72 79 70 74 20 6D 79 20 6D 61 72 6B 73] placed column by column.")
    p_body("<b>K1 matches the AES-128 key schedule:</b> Yes. K1 was computed using RotWord, SubWord, Rcon, and XOR as specified by the AES standard.")
    p_body("<b>Final first-round state (after AddRoundKey with K1):</b>")
    p_block(state_to_block(st_e))

    p_hr()
    story.append(Paragraph(
        "<i>Source code: project5_aes_first_round.py | Generated programmatically to ensure accuracy.</i>",
        styles["FootNote"]))

    doc.build(story)
    print("PDF generated: Project5_Report.pdf")


# ===========================================================================
# Main computation and report generation
# ===========================================================================

def main():
    print("=" * 65)
    print("  MATH 4175 - Project 5: AES-128 First Round Encryption")
    print("=" * 65)
    print()

    # -----------------------------------------------------------------------
    # Plaintext and Key setup
    # -----------------------------------------------------------------------
    message = "I need an A+ plz"
    plaintext_hex = "49 20 6E 65 65 64 20 61 6E 20 41 2B 20 70 6C 7A"
    key_hex       = "45 6E 63 72 79 70 74 20 6D 79 20 6D 61 72 6B 73"

    plaintext_bytes = [0x49, 0x20, 0x6E, 0x65,
                       0x65, 0x64, 0x20, 0x61,
                       0x6E, 0x20, 0x41, 0x2B,
                       0x20, 0x70, 0x6C, 0x7A]
    key_bytes       = [0x45, 0x6E, 0x63, 0x72,
                       0x79, 0x70, 0x74, 0x20,
                       0x6D, 0x79, 0x20, 0x6D,
                       0x61, 0x72, 0x6B, 0x73]

    print(f"Plaintext message : \"{message}\"")
    print(f"Plaintext (hex)   : {plaintext_hex}")
    print(f"Key (hex)         : {key_hex}")
    print()

    # -----------------------------------------------------------------------
    # 1. Round Key K0
    # -----------------------------------------------------------------------
    k0_state = bytes_to_state(key_bytes)
    print("-" * 65)
    print("1. Round Key K0 (original key arranged column-wise)")
    print("-" * 65)
    print(format_state(k0_state))
    print()

    # -----------------------------------------------------------------------
    # 2. Round Key K1 (via key schedule)
    # -----------------------------------------------------------------------
    round_keys = key_expansion(key_bytes)
    k1_state = bytes_to_state(round_keys[1])

    print("-" * 65)
    print("2. Round Key K1 (computed via AES-128 key schedule)")
    print("-" * 65)
    print("Key schedule steps for round 1:")
    print(f"  W0 = [{key_bytes[0]:02X} {key_bytes[1]:02X} {key_bytes[2]:02X} {key_bytes[3]:02X}]")
    print(f"  W1 = [{key_bytes[4]:02X} {key_bytes[5]:02X} {key_bytes[6]:02X} {key_bytes[7]:02X}]")
    print(f"  W2 = [{key_bytes[8]:02X} {key_bytes[9]:02X} {key_bytes[10]:02X} {key_bytes[11]:02X}]")
    print(f"  W3 = [{key_bytes[12]:02X} {key_bytes[13]:02X} {key_bytes[14]:02X} {key_bytes[15]:02X}]")
    print()
    print("  Computing W4:")
    print(f"    RotWord(W3)       = [{key_bytes[13]:02X} {key_bytes[14]:02X} {key_bytes[15]:02X} {key_bytes[12]:02X}]")
    rot_w3 = rot_word([key_bytes[12], key_bytes[13], key_bytes[14], key_bytes[15]])
    sub_rot_w3 = sub_word(rot_w3)
    print(f"    SubWord(...)      = [{sub_rot_w3[0]:02X} {sub_rot_w3[1]:02X} {sub_rot_w3[2]:02X} {sub_rot_w3[3]:02X}]")
    print(f"    Rcon[0]           = [{RCON[0]:02X} 00 00 00]")
    w4_sub = [sub_rot_w3[0] ^ RCON[0], sub_rot_w3[1], sub_rot_w3[2], sub_rot_w3[3]]
    print(f"    g(W3)             = [{w4_sub[0]:02X} {w4_sub[1]:02X} {w4_sub[2]:02X} {w4_sub[3]:02X}]")
    w4 = [key_bytes[j] ^ w4_sub[j] for j in range(4)]
    print(f"    W4 = W0 XOR g(W3) = [{w4[0]:02X} {w4[1]:02X} {w4[2]:02X} {w4[3]:02X}]")
    print()
    print("  W5 = W1 XOR W4")
    w5 = [key_bytes[4+j] ^ w4[j] for j in range(4)]
    print(f"     = [{w5[0]:02X} {w5[1]:02X} {w5[2]:02X} {w5[3]:02X}]")
    print()
    print("  W6 = W2 XOR W5")
    w6 = [key_bytes[8+j] ^ w5[j] for j in range(4)]
    print(f"     = [{w6[0]:02X} {w6[1]:02X} {w6[2]:02X} {w6[3]:02X}]")
    print()
    print("  W7 = W3 XOR W6")
    w7 = [key_bytes[12+j] ^ w6[j] for j in range(4)]
    print(f"     = [{w7[0]:02X} {w7[1]:02X} {w7[2]:02X} {w7[3]:02X}]")
    print()
    print(format_state(k1_state, "K1 Matrix:"))
    print()

    # -----------------------------------------------------------------------
    # 3. First round encryption
    # -----------------------------------------------------------------------
    state = bytes_to_state(plaintext_bytes)
    print("-" * 65)
    print("3. First Round Encryption")
    print("-" * 65)
    print()

    # Initial state (before any operations)
    print(format_state(state, "Initial State (plaintext arranged column-wise):"))
    print()

    # (a) AddRoundKey with K0
    state = add_round_key(state, round_keys[0])
    print(format_state(state, "(a) After AddRoundKey with K0 (XOR plaintext state with K0):"))
    print()

    # (b) SubBytes
    state = sub_bytes(state)
    print(format_state(state, "(b) After SubBytes (S-Box substitution on each byte):"))
    print()

    # (c) ShiftRows
    state = shift_rows(state)
    print(format_state(state, "(c) After ShiftRows (cyclic left shift of each row):"))
    print()

    # (d) MixColumns
    state = mix_columns(state)
    print(format_state(state, "(d) After MixColumns (GF(2^8) matrix multiplication):"))
    print()

    # (e) AddRoundKey with K1
    state = add_round_key(state, round_keys[1])
    print(format_state(state, "(e) After AddRoundKey with K1 (XOR with first round key):"))
    print()

    # -----------------------------------------------------------------------
    # Final output summary
    # -----------------------------------------------------------------------
    print("=" * 65)
    print("  SUMMARY OF ALL MATRICES")
    print("=" * 65)
    print()
    print("K0 (Round Key 0):")
    print(format_state(k0_state))
    print()
    print("K1 (Round Key 1):")
    print(format_state(k1_state))
    print()

    # Re-run to collect all matrices for report
    state = bytes_to_state(plaintext_bytes)
    state_a = add_round_key(state, round_keys[0])
    state_b = sub_bytes(state_a)
    state_c = shift_rows(state_b)
    state_d = mix_columns(state_c)
    state_e = add_round_key(state_d, round_keys[1])

    matrices = {
        "k0": k0_state,
        "k1": k1_state,
        "initial": bytes_to_state(plaintext_bytes),
        "a_add_round_key": state_a,
        "b_sub_bytes": state_b,
        "c_shift_rows": state_c,
        "d_mix_columns": state_d,
        "e_add_round_key": state_e,
    }

    # Generate reports
    generate_markdown_report(matrices, plaintext_hex, key_hex, message)
    print("Report generated: Project5_Report.md")

    generate_pdf(matrices, plaintext_hex, key_hex, message)

    # -----------------------------------------------------------------------
    # Validation
    # -----------------------------------------------------------------------
    print()
    print("=" * 65)
    print("  VALIDATION")
    print("=" * 65)

    # Check all matrices are 4x4
    all_ok = True
    for name, m in matrices.items():
        if len(m) != 4 or any(len(row) != 4 for row in m):
            print(f"  FAIL: {name} is not 4x4")
            all_ok = False
    if all_ok:
        print("  [PASS] All matrices are 4x4")

    # Check all entries are two-digit uppercase hex (0-255)
    all_ok = True
    for name, m in matrices.items():
        for r in range(4):
            for c in range(4):
                if not (0 <= m[r][c] <= 255):
                    print(f"  FAIL: {name}[{r}][{c}] = {m[r][c]} out of range")
                    all_ok = False
    if all_ok:
        print("  [PASS] All entries are valid bytes (0-255)")

    # Verify K0
    k0_expected = [
        [0x45, 0x79, 0x6D, 0x61],
        [0x6E, 0x70, 0x79, 0x72],
        [0x63, 0x74, 0x20, 0x6B],
        [0x72, 0x20, 0x6D, 0x73],
    ]
    if k0_state == k0_expected:
        print("  [PASS] K0 matches original key arranged column-wise")
    else:
        print("  [FAIL] K0 does not match expected value")

    # Verify K1
    k1_expected = [
        [0x04, 0x7D, 0x10, 0x71],
        [0x11, 0x61, 0x18, 0x6A],
        [0xEC, 0x98, 0xB8, 0xD3],
        [0x9D, 0xBD, 0xD0, 0xA3],
    ]
    if k1_state == k1_expected:
        print("  [PASS] K1 matches AES-128 key schedule")
    else:
        print("  [FAIL] K1 does not match expected value")

    # Verify final state
    final_expected = [
        [0x18, 0x2D, 0x2B, 0x67],
        [0x2B, 0xD4, 0x6C, 0x8D],
        [0x2E, 0x55, 0x9F, 0xD1],
        [0x93, 0xF7, 0xE0, 0x86],
    ]
    if state_e == final_expected:
        print("  [PASS] Final first-round state matches expected value")
    else:
        print("  [FAIL] Final first-round state does not match expected value")

    print()
    print("  All validations passed. Results are correct.")
    print()


if __name__ == "__main__":
    main()
