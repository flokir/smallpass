# smallpass
A small cli tool used to store encrypted passwords

# Usage
smallpass currently supports the following operations
## Creating a new entry
A new entry can be created by issuing  
```smallpass create [entryname]```  
You will then be prompted to enter the password and the encryption key
## Listing all entries
To show a list of all existing entries  
```smallpass list```  
This shows a list in the format of  
entryName:entryId:HashOfEncryptedData  
## Decrypting an entry
An entry can either be decrypted by name or by id

```smallpass view [entryName]``` or ```smallpass viewid [entryId]```  
An overview of the entry will be shown and you are prompted for the decryption key
# Security
Before encryption the password is padded to 256 Bytes, so that the length of the encrypted data doesn't indicate the length off the password.

For encrypting a password, the encryption key is hashed using PBKDF2 with a random salt and 10000 iterations. This hash is then used to encrypt the password with AES-256-CBC, additionally a random initialization vector is used so that in case of the same password being stored the encrypted data looks different.

# Storage format
Entries are stored unter ```~/.pw``` in files named after their ids respectively  
These files contain a json of the following format   
```
{
  "Id": "de1c37f0-3ec6-42a9-8921-22f7259f5454", // the id of the entry
  "EntryName": "string", // the name of the entry
  "PasswordHash": "string", // the base64 encoded sha-256 hash of the encrypted password
  "EncryptedPassword": "string", // the base64 encoded encrypted password
  "Iv": "string", // the base64 encoded initialization vector used for AES-256-CBC encryption
  "Salt": "string" // the base64 encoded salt that was used for the PBKDF2 hash
}
```
