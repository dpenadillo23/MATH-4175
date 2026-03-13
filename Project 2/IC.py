#NAMES: Luke Freeman, Yoshwan Pathipati, Diego Penadillo, Hiren Sai Vellanki

#PURPOSE: To find the index of coincidence of a given cyphertext. This will be used to determine the key length of a given cyphertext.

# Open file and read cyphertext
# File is one line of text with no newline characters.
file = open("cyphertext.md", "r")
cyphertext = file.read()
file.close()

# Take user input for key length guess
m = int(input("Enter in key length guess: "))

# Divide cyphertext into substrings (y1, y2, ..., ym) based on key length guess.
substrings = []
for i in range(m):
    substring = ""
    for j in range(i, len(cyphertext), m):
        substring += cyphertext[j]
    substrings.append(substring)

# Print out substrings for testing purposes
print("Substrings:")
for i in range(m):
    print(f"y{i+1}: {substrings[i]}")

# For each substring, calculate the index of coincidence (IC).