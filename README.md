## Cipher checker

Simple script to check server SSL ciphers.  
Just an automation of ```openssl s_client -connect IP:PORT -cipher CIPHER ```
  
[Inspired by ...](https://superuser.com/questions/109213/how-do-i-list-the-ssl-tls-cipher-suites-a-particular-website-offers)

Use [this page](https://ciphersuite.info/cs/) to find exact openSSL ciphers and their description.

```
usage: checker.py [-h] [--clear] [--scope SCOPE_FILE] [--ip SCOPE_IP] [--port TARGET_PORT]
                  [--ciphers CIPH_FILE] [--output OUTPUT] [--timeout TIMEOUT] [--verbose]

Small script to check SSL ciphersuits.

optional arguments:
  -h, --help           show this help message and exit
  --clear              Clear all log files before run.
  --scope SCOPE_FILE   File with IP scope.
  --ip SCOPE_IP        Single IP to check.
  --port TARGET_PORT   Port to check. Default: 443
  --ciphers CIPH_FILE  File with Ciphers. Default: weak.
  --output OUTPUT      Output dir. Default: ./
  --timeout TIMEOUT    Request timeout. Default: 1
  --verbose            Print all results.
```


Script generates files:
- success.txt - IPs accepted cipher;
- rejects.txt - IPs rejected cipher;
- no_answ.txt - IPs didn't answer;
- log.txt     - all answers for every IP/cipher.
