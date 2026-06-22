#!/usr/bin/env python3

from PIL import Image
from pyzbar.pyzbar import decode as pyzbar_decode 
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA 
from Crypto.Signature import pkcs1_15
import base64
import datetime
import email.utils
import io
import json
import os
import pathlib
import requests
import time
import urllib.parse

def parse_qr_code(image_path):
    """Parse a QR code from an image file and return its decoded text."""
    try:
        image = Image.open(image_path)
    except (FileNotFoundError, OSError) as e:
        raise ValueError(f"Could not open image '{image_path}': {e}") from e
    decoded_objects = pyzbar_decode(image)
    if not decoded_objects:
        raise ValueError("No QR code found in the image.")
    return decoded_objects[0].data.decode('utf-8')

def get_config_dir():
    """Return the platform-appropriate config directory for shimshady."""
    if os.name == "nt":
        base = os.environ.get("APPDATA") or (pathlib.Path.home() / "AppData" / "Roaming")
        return pathlib.Path(base) / "shimshady"
    return pathlib.Path.home() / ".config" / "shimshady"

def secure_permissions(path):
    """Best-effort restriction of a file to the owner (no-op where unsupported)."""
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        # Windows largely ignores POSIX modes; ACL hardening would require pywin32.
        pass

class Client:
    def __init__(self, akey=None, pkey=None, host=None, code=None, response=None, keyfile=None):
        self.akey = akey
        self.pkey = pkey 
        self.host = host
        self.code = code
        self.info = {}

        if keyfile: 
            self.import_key(keyfile)
        else:
            self.pubkey = RSA.generate(2048)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        parts = [f"{i}={getattr(self, i)!r}" for i in ("akey", "pkey", "host") if getattr(self, i)]
        return f"Client({', '.join(parts)})"

    def import_key(self, keyfile):
        """Import a public key from a PEM file."""
        if hasattr(keyfile, "read"):
            self.pubkey = RSA.import_key(keyfile.read())
        else:
            try:
                with open(keyfile, "rb") as f:
                    self.pubkey = RSA.import_key(f.read())
            except FileNotFoundError:
                raise FileNotFoundError(f"Key file '{keyfile}' not found")
            except Exception as e:
                raise ValueError(f"Failed to import key from '{keyfile}': {e}") from e 

    def export_key(self, keyfile):
        """Export the public key to a PEM file."""
        if hasattr(keyfile, "write"):
            keyfile.write(self.pubkey.export_key("PEM"))
        else:
            with open(keyfile, "wb") as f:
                f.write(self.pubkey.export_key("PEM"))
        secure_permissions(keyfile)

    def read_code(self, code):
        """Read and parse a QR code string."""
        code, host = map(lambda x: x.strip("<>"), code.split("-"))
        missing_padding = len(host) % 4
        if missing_padding:
            host += '=' * (4 - missing_padding)
        self.code = code 
        self.host = base64.b64decode(host.encode('ascii')).decode('ascii')

    def import_response(self, response_path_or_dict):
        """Import and verify a response path or dict."""
        if isinstance(response_path_or_dict, dict):
            response = response_path_or_dict 
            if "response" in response: 
                response = response["response"]
        else:
            with open(response_path_or_dict, "r") as f:
                response = json.load(f)
            if "response" in response:
                response = response["response"]
        self.info = response 
        self.akey = response["akey"]
        self.pkey = response["pkey"]
        if not self.host and "host" in response and response["host"]:
            self.host = response["host"]
        elif self.host:
            self.info["host"] = self.host

    def export_response(self, response_path):
        """Export the response to a JSON file."""
        if self.host and "host" not in self.info:
            self.info["host"] = self.host
        with open(response_path, "w") as f:
            json.dump(self.info, f, indent=4)
        secure_permissions(response_path)

    def activate(self):
        """Activate the client with the server."""
        if not self.code:
            raise ValueError("Code is null, cannot activate. Please provide a code first.")
        params = {
                "customer_protocol": "1",
                "pubkey": self.pubkey.publickey().export_key("PEM").decode('ascii'),
                "pkpush": "rsa-sha512",
                "jailbroken": "false",
                "architecture": "arm64",
                "region": "US",
                "app_id": "com.duosecurity.duomobile",
                "full_disk_encryption": "true",
                "passcode_status": "true",
                "platform": "Android",
                "app_version": "4.85.0",
                "app_build_number": "4850000",
                "version": "12",
                "manufacturer": "unknown",
                "language": "en",
                "model": "Browser Extension",
                "security_patch_level": "2021-02-01"
        }
        r = requests.post(f"https://{self.host}/push/v2/activation/{self.code}", params=params)
        response = r.json()
        self.import_response(response)

    def generate_signature(self, method, path, time, data):
        """Generate an authorization signature for a request."""
        message = (time + "\n" +
                   method + "\n" +
                   self.host.lower() + "\n" +
                   path + "\n" +
                   urllib.parse.urlencode(data)).encode('ascii')
        h = SHA512.new(message)
        signature = pkcs1_15.new(self.pubkey).sign(h)
        auth = ("Basic "+base64.b64encode((self.pkey + ":" +
                base64.b64encode(signature).decode('ascii')).encode('ascii')).decode('ascii'))
        return auth

    def get_transactions(self):
        """Get a transaction from the server."""
        dt = datetime.datetime.now(datetime.UTC)
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/transactions"
        data = {
                "akey": self.akey,
                "fips_status": "1",
                "hsm_status": "true",
                "pkpush": "rsa-sha512"
               }
        signature = self.generate_signature("GET", path, time, data)
        r = requests.get(f"https://{self.host}{path}", params=data, headers={
            "Authorization": signature, "x-duo-date": time, "host": self.host})
        return r.json()

    def reply_transaction(self, txid, answer):
        """Reply to a transaction."""
        dt = datetime.datetime.now(datetime.UTC)
        time = email.utils.format_datetime(dt)
        path = f"/push/v2/device/transactions/{txid}"
        data = {
                "akey": self.akey,
                "answer": answer,
                "fips_status": "1",
                "hsm_status": "true",
                "pkpush": "rsa-sha512",
               }
        signature = self.generate_signature("POST", path, time, data)
        r = requests.post(f"https://{self.host}{path}", data=data, headers={
            "Authorization": signature, "x-duo-date": time, "host": self.host, "txId": txid})
        return r.json()

    def register(self, token):
        """Register the client with a token."""
        dt = datetime.datetime.now(datetime.UTC)
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/registration"
        data = {
                "akey": self.akey,
                "token": token
               }
        signature = self.generate_signature("POST", path, time, data)
        r = requests.post(f"https://{self.host}{path}", params=data, headers={
            "Authorization": signature, "x-duo-date": time, "host": self.host})
        return r.json()

def get_code_from_user():
    """Get activation code from user via QR code or manual input."""
    user_input = input("Do you have a QR code to decode? (y/n) :").strip().lower()
    if user_input in ['y', 'yes']:
        image_path = input("Please enter the path to the QR code image: ").strip()
        try:
            return parse_qr_code(image_path)
        except Exception as e:
            print(f"Failed to process QR code: {e}")
            return None 
    elif user_input in ['n', 'no']:
        return input("Please enter your code:").strip()
    else: 
        print("Invalid input, please enter 'y' or 'n'.")
        return None 

def main(): 
    """Main function for CLI interaction."""
    c = Client()
   
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True) 
    key_path = config_dir / "key.pem"
    response_path = config_dir / "response.json"

    key_exists = key_path.exists()
    if key_exists: 
        c.import_key(key_path)
        secure_permissions(key_path)
    else:
        c.export_key(key_path)

    if response_path.exists() and key_exists:
        c.import_response(response_path)
        secure_permissions(response_path)
       
        if not c.host: 
            code = get_code_from_user()
            if code:
                c.read_code(code)
                c.activate()
                c.export_response(response_path)
            else: 
                print("No code provided, exiting.")
                return 
    else:
        # Fresh setup 
        code = get_code_from_user()
        if not code: 
            print("No code provided, exiting.")
            return 
        c.read_code(code)
        c.activate()
        c.export_response(response_path)

    timeout = 180
    while timeout >= 0:
        try:
            r = c.get_transactions()
        except requests.exceptions.ConnectionError:
            print("Connection error")
            time.sleep(5)
            timeout -= 5
            continue
        if "stat" not in r or r["stat"] != "OK":
            print(json.dumps(r, indent=4))
            raise ValueError("Check the response above for errors.")
        t = r["response"]["transactions"]
        if len(t):
            for tx in t: 
                c.reply_transaction(tx["urgid"], "approve")
                time.sleep(1)
                return
        time.sleep(5)
        timeout -= 5 
    print("No transactions found, exiting.")

if __name__ == "__main__":
    """lol"""
    main()
