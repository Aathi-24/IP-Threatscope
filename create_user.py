#!/usr/bin/env python3
"""
Admin script — create a new IP Threatscope user account from the command line.

Usage:
    python3 create_user.py user@company.com TemporaryPassword123

Role is automatic: any email ending in @nakoatech.com becomes an admin
(redirected to the Admin Console on login); every other domain is a
regular user. There's no separate flag for this.

Run this from the IP_Reputation_Checker directory. After creation, email
the credentials to the user and instruct them to change their password
on first login.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.auth import register_user, get_user, get_role_for_email

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 create_user.py <email> <password>")
        print("")
        print("Example:")
        print("  python3 create_user.py john.doe@company.com TempPass2024!")
        sys.exit(1)

    email    = sys.argv[1].strip().lower()
    password = sys.argv[2]
    role     = get_role_for_email(email)

    print(f"Creating account for: {email}  (role: {role})")
    ok, msg = register_user(email, password)

    if ok:
        print(f"✓ {msg}")
        print("")
        print("Next steps:")
        print(f"  1. Email credentials to {email}")
        print(f"     User ID : {email}")
        print(f"     Password: {password}")
        print(f"  2. Instruct the user to change their password immediately")
        if role == "admin":
            print(f"     after first login (Admin Console → My Password).")
        else:
            print(f"     after first login (Settings → Security tab).")
    else:
        print(f"✗ Failed: {msg}")
        sys.exit(1)

if __name__ == "__main__":
    main()
