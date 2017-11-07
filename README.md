## NAME
pws - encrypted password storage

## SYNOPSIS
	pws [ -f file ] [ command ]

## DESCRIPTION
Pws maintains an encrypted database of passwords. When invoked with no arguments, pws prompts for the master password and prints the decrypted database to standard output. Each line has the following format:

	server / username / email / password / notes

If no database file already exists, pws prompts for a new master password and uses that to initialize one.

## OPTIONS
**-f** *FILE*  
Specify the path to the database file. The default path is ".pws" under the user's home directory.

## COMMANDS
**a**  
Interactively add a new database entry, or edit the entry with the given server+username combination if it already exists. Spaces are allowed in all fields.

**del** *SERVER* *USERNAME*  
Delete the entry for the given *SERVER*-*USERNAME* pair.

**p**  
Change the master password.

## IMPLEMENTATION
The database file has the following layout:

	(4 bytes)       magic ("pws2")
	(4 bytes)       number of key derivation iterations, little-endian
	(16 bytes)      key derivation salt
	(12 bytes)      cipher nonce
	(rest of data)  database ciphertext

The database is encrypted by AES-128 GCM using a key derived from the master password by PBKDF2 SHA-512.

The salt and nonce are randomized on every write to the database.
