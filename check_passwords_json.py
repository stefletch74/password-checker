import hashlib
import requests
import json

def check_bitwarden_login_pwned(json_file):
    """Checks Bitwarden logins against the HIBP Range API and returns pwned logins."""

    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        pwned_passwords = []
        for item in data['items']:
            if item['type'] == 1:
                uri = item['login']['uris'][0]['uri'] if item['login']['uris'] else None
                username = item['login']['username']
                password = item['login']['password']
                if password:
                    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
                    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

                    url = f'https://api.pwnedpasswords.com/range/{prefix}'
                    response = requests.get(url)

                    if response.status_code == 200:
                        hashes = (line.split(':') for line in response.text.splitlines())
                        for s, count in hashes:
                            if s == suffix:
                                pwned_passwords.append((uri, username, password))
                                break

                    else:
                        print(f"Error checking password for {username} ({uri}): API request failed with status code {response.status_code}")
                else:
                    print(f"Warning: No password found for {username} ({uri}). Skipping.")

        return pwned_passwords

    except FileNotFoundError:
        print(f"Error: File '{json_file}' not found.")
        return None
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in '{json_file}'.")
        return None
    except KeyError:
        print(f"Error: Unexpected JSON structure in '{json_file}'.")
        return None

# Example Usage:
json_file = r"C:\Users\smfle\Downloads\bitwarden_export_20250228094914.json"
logins = check_bitwarden_login_pwned(json_file)

if logins:
    print("Pwned logins (uri, username, password):")
    for uri, username, password in logins:
        print(f"- URI: {uri}, Username: {username}, Password: {password}")
else:
    print("No pwned logins found.")