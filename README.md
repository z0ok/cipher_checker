## Cipher checker

Simple script to check server SSL ciphers.

[Inspired by ...](https://superuser.com/questions/109213/how-do-i-list-the-ssl-tls-cipher-suites-a-particular-website-offers)

```
usage: checker.py [-h] [--clear] [--scope SCOPE_FILE] [--ip SCOPE_IP] [--port TARGET_PORT]
                  [--ciphers CIPH_FILE] [--output OUTPUT] [--verbose]

Small script to check SSL ciphersuits.

optional arguments:
  -h, --help           show this help message and exit
  --clear              Clear all log files before run.
  --scope SCOPE_FILE   File with IP scope.
  --ip SCOPE_IP        Single IP to check.
  --port TARGET_PORT   Port to check. Default: 443
  --ciphers CIPH_FILE  File with Ciphers. Default: SHA1
  --output OUTPUT      Output dir. Default: ./
  --verbose            Print all results.
```


Generates list of files:
- success.txt - IPs accepted cipher;
- rejects.txt - IPs rejected cipher;
- no_answ.txt - IPs didn't answer;
- log.txt     - all answers for every IP/cipher.
