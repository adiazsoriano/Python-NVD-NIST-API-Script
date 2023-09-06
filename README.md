# Python-NVD-NIST-API-Script
The python version of: https://github.com/adiazsoriano/PHP-NVD-NIST-API-script . It is a CLI based script that takes in command-line arguments. This version may contain improvements over the PHP counterpart.

## The .env file
The script reads from the .env file inside the folder if present. Or it reads from the environment using the OS module. Otherwise it defaults to not having an api key.
```dotenv
api_key='API KEY GOES HERE'
```