"""Create a private .env with standard-library key generation; never overwrite."""

import argparse
import base64
import getpass
import json
import os
import secrets
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Configure local Docker Compose login template")
    parser.add_argument("--username", default="admin")
    args = parser.parse_args()
    password = getpass.getpass("Initial administrator password (12-128 characters): ")
    if not 12 <= len(password) <= 128:
        parser.error("Password must contain 12-128 characters.")
    # JSON-quoted dotenv values preserve whitespace and escape metacharacters.
    # Restrict characters dotenv would expand, rather than silently altering passwords.
    if any(char in password for char in ('$', '\n', '\r', '\0')):
        parser.error("For bootstrap .env only, passwords must not contain $, line breaks or NUL.")
    values = {
        "SECRET_KEY": secrets.token_hex(32),
        "TOTP_ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        "TOTP_ISSUER_NAME": "Flask Accounts",
        "ADMIN_USERNAME": args.username,
        "ADMIN_INITIAL_PASSWORD": password,
        "PUBLIC_ORIGIN": "http://localhost:8000",
        "WEBAUTHN_RP_ID": "localhost",
    }
    fd = os.open(Path(".env"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write("\n".join(
            f"{key}={json.dumps(value, ensure_ascii=False)}" for key, value in values.items()
        ) + "\n")
    print("Created private .env. Run docker compose up --build, then open http://localhost:8000.")


if __name__ == "__main__":
    main()
