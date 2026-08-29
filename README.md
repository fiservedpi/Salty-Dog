<p align="center">
<<<<<<< HEAD
  <img src="./assets/py-vault-logo.jpg" alt="Py Vault logo — a secure vault emblem" width="320" />
=======
  <img
    src="./src/py_vault/assets/py-vault-logo.jpg"
    alt="Py Vault logo — a secure vault emblem"
    width="260"
  />
</p>

<h1 align="center">🔐 <code>Py Vault</code></h1>

<p align="center">
  <strong>A local-first, encrypted secrets vault for Python.</strong>
</p>

<p align="center">
  <sub>PRIVATE • PORTABLE • SELF-HOSTED</sub>
>>>>>>> 189c1d27f48fa1ccdbefc1a2c33c9780444adf18
</p>

<h1 align="center">Py Vault</h1>

<p align="center">
  A lightweight, local-first Python vault for securely storing and retrieving secrets from the command line or your applications.
</p>

> **Note:** Replace the example commands, package name, and configuration details below with the exact interfaces implemented by your project.

## Features

- Encrypted local storage for secrets and sensitive values
- Simple Python API for application integrations
- Command-line workflow for managing vault entries
- Master-password-based access
- JSON-friendly values for structured configuration
- Export and import support for backups and migration
- Small, auditable, and easy to self-host

## Requirements

- Python 3.10 or newer
- `pip`
- A secure master password

## Installation

Clone the repository, then create and activate an isolated Python environment:

```bash
git clone https://github.com/<your-user>/py-vault.git
cd py-vault

python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\Activate.ps1     # PowerShell

pip install --upgrade pip
pip install -r requirements.txt
```

If the project is packaged, install it in editable mode for development:

```bash
pip install -e .
```

## Quick start

Initialize a new vault:

```bash
py-vault init
```

You will be prompted to create a master password. Use a strong, unique password stored in a password manager. It is required to decrypt the vault; if it is lost, stored data may be unrecoverable.

Add a secret:

```bash
py-vault set github.token "ghp_example_token"
```

Retrieve it:

```bash
py-vault get github.token
```

List entry names without revealing their values:

```bash
py-vault list
```

Remove an entry:

```bash
py-vault delete github.token
```

## Python usage

Use Py Vault in Python applications when secrets should remain outside source control and plaintext configuration files.

```python
from py_vault import Vault

vault = Vault.open()
github_token = vault.get("github.token")

print(github_token)
```

Store values programmatically:

```python
from py_vault import Vault

vault = Vault.open()
vault.set("home_assistant.token", "example-long-lived-access-token")
vault.save()
```

Store JSON-compatible structured values if your vault implementation supports them:

```python
vault.set("service.config", {
    "host": "example.local",
    "port": 443,
    "verify_tls": True,
})
vault.save()
```

## Configuration

By default, keep the encrypted vault file outside the repository. Conventional paths include:

| Platform | Suggested location |
| --- | --- |
| Linux | `~/.config/py-vault/vault.enc` |
| macOS | `~/Library/Application Support/py-vault/vault.enc` |
| Windows | `%APPDATA%\py-vault\vault.enc` |

Override the vault location with an environment variable:

```bash
export PY_VAULT_PATH="$HOME/.config/py-vault/vault.enc"
```

PowerShell:

```powershell
$env:PY_VAULT_PATH = "$env:APPDATA\py-vault\vault.enc"
```

Do not commit vault files, key files, exports, `.env` files, or real tokens to Git.

## Command reference

```text
py-vault init                 Create a new encrypted vault
py-vault set <key> <value>    Create or update a value
py-vault get <key>            Read a value
py-vault list                 List stored keys
py-vault delete <key>         Delete a value
py-vault export <file>        Create an encrypted backup or export
py-vault import <file>        Restore or merge an export
py-vault change-password      Rotate the master password
```

Use the built-in help for the authoritative options supported by your version:

```bash
py-vault --help
py-vault <command> --help
```

## Security notes

- Treat the master password as the root credential for all vault contents.
- Never place real secrets in examples, issue reports, CI logs, screenshots, or shell history.
- Back up the encrypted vault in a location separate from the device running it.
- Restrict vault-file permissions to the account that owns the vault.
- Prefer environment variables, secret stores, or CI secret managers when injecting a vault password into automated workflows.
- Rotate credentials immediately if a secret may have been exposed.

## Development

Install development dependencies:

```bash
pip install -r requirements-dev.txt
```

Run tests:

```bash
pytest
```

Format and lint the codebase:

```bash
ruff format .
ruff check .
```

## Project layout

```text
py-vault/
├── assets/
│   └── py-vault-logo.jpg  # Project logo
├── py_vault/              # Application package
├── tests/                 # Automated tests
├── requirements.txt       # Runtime dependencies
├── requirements-dev.txt   # Development dependencies
├── pyproject.toml         # Build and tool configuration
└── README.md              # Project documentation
```

## Backup and recovery

Back up the encrypted vault file regularly. Test recovery by restoring a copy on another machine or in an isolated directory. A backup is useful only when it remains readable and protected by a master password you can still access.

Example:

```bash
py-vault export ~/backups/py-vault-backup.enc
```

Store backups in an encrypted, access-controlled location. Do not rely on a single disk, server, or cloud account.

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Add or update tests for your changes.
4. Run the test and lint commands.
5. Open a pull request with a clear description of the change.

Do not submit live credentials, encrypted vault files, or decrypted exports in pull requests.

## License

Add the project license here, for example:

```text
MIT License
```
