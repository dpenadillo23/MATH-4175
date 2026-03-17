NAMES: Luke Freeman, Yoshwan Pathipati, Diego Penadillo, Hiren Sai Vellanki

---

# Part 1:

- Step 1: m = 6

  y1: IC = 0.0390
  y2: IC = 0.0451
  y3: IC = 0.0436
  y4: IC = 0.0447
  y5: IC = 0.0422
  y6: IC = 0.0491
  Average IC = 0.0439

- Step 2: m = 7

  y1: IC = 0.0713
  y2: IC = 0.0713
  y3: IC = 0.0682
  y4: IC = 0.0614
  y5: IC = 0.0683
  y6: IC = 0.0623
  y7: IC = 0.0679
  Average IC = 0.0672

- Step 3: m = 8

  y1: IC = 0.0422
  y2: IC = 0.0434
  y3: IC = 0.0418
  y4: IC = 0.0456
  y5: IC = 0.0434
  y6: IC = 0.0445
  y7: IC = 0.0435
  y8: IC = 0.0494
  Average IC = 0.0442

- Step 4:

  Yes. When m = 7, all seven substrings yield IC values between 0.0614 and 0.0713,
  all close to the expected English plaintext IC of ~0.065. This indicates that each
  coset consists of characters shifted by a single fixed key letter, producing
  English-like letter distributions. For m = 6 and m = 8, the average ICs are 0.0439
  and 0.0442 respectively — both close to the random text IC of ~0.038 — indicating
  that those key length guesses mix characters from different shifts, destroying the
  English frequency pattern. Therefore, the IC method confirms that m = 7 is the
  correct key length.

---

# Part 2:

Using the mutual index of coincidence method on each of the 7 cosets (m = 7),
we test all 26 possible shifts for each coset and select the shift g that maximizes:

  M_g = sum over j of [ (f_j / n) * p_(j-g mod 26) ]

where f_j is the frequency of letter j in the coset, n is the coset length,
and p_i is the standard English letter frequency for letter i.

| Coset | Best Shift (g) | Key Letter | M_g (best) |
|-------|----------------|------------|------------|
|  y1   |       19       |     T      |  0.06518   |
|  y2   |       22       |     W      |  0.06731   |
|  y3   |        8       |     I      |  0.06565   |
|  y4   |       18       |     S      |  0.06211   |
|  y5   |       19       |     T      |  0.06607   |
|  y6   |        4       |     E      |  0.06290   |
|  y7   |        3       |     D      |  0.06466   |

**Keyword: TWISTED**

The keyword TWISTED is a meaningful English word, confirming the key is correct.

---

# Part 3:

The decrypted plaintext (keyword: TWISTED) is:

The department of justice has been and will always be committed to protecting the
liberty and security of those whom we serve. In recent months however we have on a
new scale seen mainstream products and services designed in a way that gives users
sole control over access to their data. As a result law enforcement is sometimes
unable to recover the content of electronic communications from the technology
provider even in response to a court order or duly authorized warrant issued by a
federal judge. For example many communications services now encrypt certain
communications by default with the key necessary to decrypt the communications
solely in the hands of the end user. This applies both when the data is in motion
over electronic networks or at rest on an electronic device. If the communications
provider is served with a warrant seeking those communications the provider cannot
provide the data because it has designed the technology such that it cannot be
accessed by any third party. We do not have any silver bullets and the discussions
within the executive branch are still ongoing. While there has not yet been a
decision whether to seek legislation we must work with congress industry academics
privacy groups and others to craft an approach that addresses all of the multiple
competing concerns that have been the focus of so much debate. But we can all agree
that we will need ongoing honest and informed public debate about how best to
protect liberty and security in both our laws and our technology.