# Secure Notes
Web service for storing encrypted notes and files

## Premise
- The server has no knowledge of the stored content
- The server only stores:
    - Encrypted content
    - Encrypted symmetric key to en-/decrypt content
    - Asymmetric keys to en-/decrypt symmetric key
    - Access control list
- The server in unaware of the passphrase for the asymmetric key

## Contents
- Web service written in Python with Django and Django REST Framework
- Example client