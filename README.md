# shimshady

shimshady is a Duo 2FA shim that can parse QR codes or accept activation codes, tested for *nix thus far.
- It creates RSA keys, activates with Duo servers, and approves authentication requests 
- Requires system dependency: [zbar](https://github.com/mchehab/zbar) for QR code processing
- Uses [uv](https://docs.astral.sh/uv/) for dependency management

## Building and Usage 

- After cloning and changing directory, `uv tool install .` will install.
- CLI script entry point: `shimshady` command.
- Probably a good idea to run `chmod -R 0600 ~/.config/shimshady` after initial setup.
