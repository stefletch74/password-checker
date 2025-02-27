import hashlib
import requests

def check_pwned_passwords(password_file):
    """Checks passwords from a file against the HIBP Range API."""

    try:
        with open(password_file, 'r') as f:
            passwords = [line.strip() for line in f]
    except FileNotFoundError:
        print(f"Error: Password file '{password_file}' not found.")
        return

    pwned_passwords = []

    for password in passwords:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]

        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        response = requests.get(url)

        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for s, count in hashes:
                if s == suffix:
                    pwned_passwords.append(password)
                    break  # Password found, no need to check other suffixes

        else:
            print(f"Error checking password '{password}': API request failed with status code {response.status_code}")

    if pwned_passwords:
        print("\nExposed Passwords:")
        for pwned_password in pwned_passwords:
            print(f"- {pwned_password}")
    else:
        print("\nNo exposed passwords found.")

# Example Usage:
password_file = '<mypasswords>.csv'  # Replace with your password file's name
check_pwned_passwords(password_file)