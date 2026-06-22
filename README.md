# shimshady

Shimshady is a Duo 2FA shim that can parse QR codes or accept activation codes, tested for *nix thus far, but should support Windows now.
- It creates RSA keys, activates with Duo servers, and approves authentication requests.
- It requires system dependency [zbar](https://github.com/mchehab/zbar) for QR code processing on *nix (this is packaged as a wheel in Windows Python, go figure.)
- It uses [uv](https://docs.astral.sh/uv/) for dependency management.

## Building and Usage 

- After cloning and changing directory, `uv tool install .` will install.
- CLI script entry point: `shimshady` command.
- Probably a good idea to run `chmod -R 0600 ~/.config/shimshady` after initial setup.
