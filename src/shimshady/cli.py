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
import pathlib
import requests
import time
import urllib.parse 

def parse_qr_code(image_path):
    """Parse a QR code from an image file."""
    image = Image.open(image_path)
    try:
        decoded_objects = pyzbar_decode(image)
        if decoded_objects:
            return decoded_objects[0].data.decode('utf-8') 
    except Exception as e:
        raise ValueError("No QR code found in the image.") from e 
   
class Client:
    def __init__(self, akey=None, pkey=None, host=None, code=None, response=None, keyfile=None):
        if keyfile:
            self.import_key(keyfile)
        else:
            self.pubkey = RSA.generate(2048)

        self.akey = akey
        self.pkey = pkey 
        self.host = host
        self.info = {}

        if code: 
            self.read_code(code)
        if response:
            self.import_response(response) 

    def __str__(self):
        return repr(self)

    def __repr__(self):
        parts = [f"{i}={getattr(self, i)!r}" for i in ("akey", "pkey", "host") if getattr(self, i)]
        return f"Client({', '.join(parts)})"

    def import_key(self, keyfile):
        """Import a public key from a PEM file."""
        if issubclass(type(keyfile), io.IOBase):
            self.pubkey = RSA.import_key(keyfile.read())
        else: 
            try:
                if hasattr(keyfile, "read"):
                    self.pubkey = RSA.import_key(keyfile.read())
                    return
                else:
                    with open(keyfile, "rb") as f:
                        self.pubkey = RSA.import_key(f.read())
            except FileNotFoundError:
                raise FileNotFoundError(f"Key file '{keyfile}' not found.")
            except Exception as e:
                raise ValueError(f"Failed to import key from '{keyfile}': {e}")

    def export_key(self, keyfile):
        """Export the public key to a PEM file."""
        if hasattr(keyfile, "write"):
            keyfile.write(self.pubkey.export_key("PEM"))
        else:
            with open(keyfile, "wb") as f:
                f.write(self.pubkey.export_key("PEM"))

    def read_code(self, code):
        """Read and parse a QR code string."""
        code, host = map(lambda x: x.strip("<>"), code.split("-"))
        missing_padding = len(host) % 4
        if missing_padding:
            host += '=' * (4 - missing_padding)
        self.code = code 
        #self.host = base64.urlsafe_b64decode(host.encode('ascii')).decode('ascii')
        self.host = base64.b64decode(host.encode('ascii')).decode('ascii')

    def import_response(self, response_path):
        """Import and verify a response path."""
        with open(response_path, "r") as f:
            response = json.load(f)
        if "response" in response:
            response = response["response"]
        self.info = response 
        if self.host and ("host" not in self.info or self.info["host"]):
            self.info["host"] = self.host
        elif not self.host and ("host" in self.info and self.info["host"]):
            self.host = self.info["host"]
        self.akey = response["akey"]
        self.pkey = response["pkey"]

    def export_response(self, response_path):
        """Export the response to a JSON file."""
        if self.host and ("host" not in self.info or self.info["host"]):
            self.info["host"] = self.host
        with open(response_path, "w") as f:
            json.dump(self.info, f, indent=4)

    def activate(self):
        """Activate the client with the server."""
        if self.code:
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
                    "app_version": "3.49.0",
                    "app_build_number": "323001",
                    "version": "11",
                    "manufacturer": "unknown",
                    "language": "en",
                    "model": "Browser Extension",
                    "security_patch_level": "2021-02-01"
            }
            r = requests.post(f"https://{self.host}/push/v2/activation/{self.code}", params=params)
            response = r.json()
            self.import_response(response)
        else:
            raise ValueError("Code is null, cannot activate.")

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

def main(): 
    """Main function for CLI interaction."""
    code = ""
    host = ""
    c = Client()
    key_exists = False 
    # use canonical cross-platform unix home config directory path as canonical place to be 
    config_dir = pathlib.Path.home() / ".config" / "shimshady"
    config_dir.mkdir(parents=True, exist_ok=True)
    key_path = config_dir / "key.pem"
    if key_path.exists():
        key_exists = True 
        c.import_key(key_path)
    else: 
        c.export_key(key_path)

    response_path = config_dir / "response.json"
    if response_path.exists() and key_exists:
        c.import_response(response_path)
        if code:
            c.read_code(code)
        if not c.host and host:
            c.host = host
        if not c.host:
            user_input = input("Do you have a QR code to decode? (y/n) :").strip().lower()
            if user_input in ['y', 'yes']:
                image_path = input("Please enter the path to the QR code image: ").strip()
                try:
                    code = parse_qr_code(image_path)
                except Exception as e:
                    print(f"failed to process QR code: {e}")
            elif response in ['n', 'no']:
                code = input("Please enter your code:")
                if code:
                    c.read_code(code)
            c.export_response(response_path)
    else:
        if not code: 
            user_input = input("Do you have a QR code to decode? (y/n) :").strip().lower()
            if user_input in ['y', 'yes']:
                image_path = input("Please enter the path to the QR code image: ").strip()
                try:
                    code = parse_qr_code(image_path)
                except Exception as e:
                    print(f"failed to process QR code: {e}")
            elif response in ['n', 'no']:
                code = input("Please enter your code:")
                if code:
                    c.read_code(code)
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
    return 

if __name__ == "__main__":
    """lol"""
    main()
