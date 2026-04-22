#!/usr/bin/env python3
"""
csc_cert.py - Download signed SSH certificates from CSC signing service.

Cross-platform CLI tool supporting ssh-agent (all platforms) and
Pageant (Windows only) integration.

Usage:
    python csc_cert.py -u <username> [-s] [-v] [-r] [-a mode] [public_key.pub]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import webbrowser
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple
from urllib.error import URLError, HTTPError

__version__ = "1.0.0"

# Constants
BASE_URL = "https://my.csc.fi"
USERNAME_PATTERN = re.compile(r'^[a-z0-9_-]+$')


@dataclass
class CertificateInfo:
    """Information about a certificate's validity."""
    is_valid: bool
    expiry: Optional[datetime]
    error: Optional[str] = None


@dataclass
class Config:
    """Runtime configuration from CLI arguments."""
    username: str
    public_key_path: Path
    agent_mode: str
    silent: bool
    verbose: bool
    refresh: bool
    create_ppk: bool = True

    @property
    def is_ppk(self) -> bool:
        """Whether the input key is a PPK file."""
        return self.public_key_path.suffix == '.ppk'

    @property
    def private_key_path(self) -> Path:
        """Derive private key path from public key path."""
        return self.public_key_path.with_suffix('')

    @property
    def cert_path(self) -> Path:
        """Certificate path following OpenSSH convention: <key>-cert.pub"""
        return self.private_key_path.parent / f"{self.private_key_path.name}-cert.pub"

    @property
    def ppk_path(self) -> Path:
        """PPK path for Windows Pageant (cert-embedded)."""
        stem = self.private_key_path.name
        return self.private_key_path.parent / f"{stem}-cert.ppk"


# =============================================================================
# Logging utilities
# =============================================================================

def log(message: str, config: Config, verbose_only: bool = False) -> None:
    """Print message to stderr respecting silent/verbose modes."""
    if config.silent:
        return
    if verbose_only and not config.verbose:
        return
    print(message, file=sys.stderr)


def log_warning(message: str, config: Config) -> None:
    """Print warning message (only in verbose mode)."""
    if config.verbose:
        print(f"Warning: {message}", file=sys.stderr)


# =============================================================================
# Core utility functions
# =============================================================================

def find_default_public_key() -> Path:
    """
    Find SSH public key in ~/.ssh directory.
    Prefers ed25519 over RSA. On Windows, also checks for PPK files.
    """
    ssh_dir = Path.home() / '.ssh'
    candidates = [
        ssh_dir / 'id_ed25519.pub',
        ssh_dir / 'id_rsa.pub',
    ]
    if platform.system() == 'Windows':
        candidates += [
            ssh_dir / 'id_ed25519.ppk',
            ssh_dir / 'id_rsa.ppk',
        ]
    for path in candidates:
        if path.exists():
            return path
    tried = 'id_ed25519.pub, id_rsa.pub'
    if platform.system() == 'Windows':
        tried += ', id_ed25519.ppk, id_rsa.ppk'
    raise FileNotFoundError(
        f"No SSH public key found in {ssh_dir} (tried {tried})"
    )


def validate_username(username: str) -> None:
    """Validate username format (lowercase letters, numbers, underscore, hyphen)."""
    if not USERNAME_PATTERN.match(username):
        raise ValueError(
            "Username must contain only lowercase letters, numbers, underscore, or hyphen"
        )


def compute_fingerprint_from_bytes(key_bytes: bytes) -> str:
    """
    Compute SHA256 fingerprint from raw SSH wire-format key bytes.

    Returns fingerprint in format: SHA256:base64_without_padding
    """
    digest = hashlib.sha256(key_bytes).digest()
    b64 = base64.b64encode(digest).decode('ascii').rstrip('=')
    return f"SHA256:{b64}"


def compute_fingerprint(public_key_path: Path) -> str:
    """
    Read OpenSSH public key and compute SHA256 fingerprint.

    Returns fingerprint in format: SHA256:base64_without_padding
    """
    content = public_key_path.read_text()
    fields = content.split()
    if len(fields) < 2:
        raise ValueError("Invalid public key format")

    key_bytes = base64.b64decode(fields[1])
    return compute_fingerprint_from_bytes(key_bytes)


def parse_ppk_header(ppk_path: Path) -> Tuple[str, str]:
    """
    Parse key type and public-key base64 from a PuTTY PPK (v2 or v3) file.

    The public key section is always unencrypted, even for encrypted PPKs.
    Returns (key_type, b64_data) where key_type is e.g. 'ssh-ed25519'
    and b64_data is the concatenated base64 of the Public-Lines section.
    """
    content = ppk_path.read_text()
    lines = content.splitlines()

    if not lines or not lines[0].startswith('PuTTY-User-Key-File-'):
        raise ValueError(f"Not a valid PPK file: {ppk_path}")

    key_type = lines[0].split(':', 1)[1].strip()

    # Find "Public-Lines: N" and read the next N lines of base64
    i = 0
    while i < len(lines):
        if lines[i].startswith('Public-Lines:'):
            count = int(lines[i].split(':')[1].strip())
            public_lines_b64 = lines[i + 1 : i + 1 + count]
            break
        i += 1
    else:
        raise ValueError(f"No Public-Lines found in PPK file: {ppk_path}")

    b64_data = ''.join(public_lines_b64)
    return key_type, b64_data


def parse_ppk_public_key(ppk_path: Path) -> bytes:
    """
    Parse public key bytes from a PuTTY PPK (v2 or v3) file.

    Returns raw SSH wire-format key bytes (same as the base64 field in .pub files).
    """
    _, b64_data = parse_ppk_header(ppk_path)
    return base64.b64decode(b64_data)


def check_certificate_validity(cert_path: Path) -> CertificateInfo:
    """
    Check if an existing certificate is still valid.

    Uses ssh-keygen -L to inspect the certificate.
    """
    if not cert_path.exists():
        return CertificateInfo(is_valid=False, expiry=None)

    try:
        result = subprocess.run(
            ['ssh-keygen', '-L', '-f', str(cert_path)],
            capture_output=True,
            text=True,
            errors='replace',
        )
        if result.returncode != 0:
            return CertificateInfo(
                is_valid=False,
                expiry=None,
                error=f"ssh-keygen failed: {result.stderr}"
            )

        # Parse "Valid: from YYYY-MM-DDTHH:MM:SS to YYYY-MM-DDTHH:MM:SS"
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('Valid:'):
                parts = line.split(' to ')
                if len(parts) == 2:
                    valid_to = parts[1].strip()
                    expiry = datetime.strptime(valid_to, '%Y-%m-%dT%H:%M:%S')
                    is_valid = datetime.now() < expiry
                    return CertificateInfo(is_valid=is_valid, expiry=expiry)

        return CertificateInfo(
            is_valid=False,
            expiry=None,
            error="Could not parse certificate validity"
        )
    except Exception as e:
        return CertificateInfo(is_valid=False, expiry=None, error=str(e))


def check_ppk_certificate_validity(ppk_path: Path) -> CertificateInfo:
    """
    Check certificate validity from a cert-embedded PPK file.

    Extracts the certificate from the PPK's public key section,
    writes it to a temp file, and checks with ssh-keygen.
    """
    if not ppk_path.exists():
        return CertificateInfo(is_valid=False, expiry=None)

    try:
        key_type, b64_data = parse_ppk_header(ppk_path)
        if '-cert' not in key_type:
            return CertificateInfo(is_valid=False, expiry=None)

        # Write temp OpenSSH cert file and check validity
        with tempfile.NamedTemporaryFile(mode='w', suffix='-cert.pub', delete=False) as f:
            f.write(f"{key_type} {b64_data}\n")
            temp_path = Path(f.name)
        try:
            return check_certificate_validity(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    except Exception as e:
        return CertificateInfo(is_valid=False, expiry=None, error=str(e))


def create_payload(fingerprint: str, username: str) -> str:
    """Create base64-encoded JSON payload for the signing service."""
    payload = {
        'fingerprint': fingerprint,
        'userCn': username,
    }
    json_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    return base64.b64encode(json_bytes).decode('ascii')


# =============================================================================
# User interaction functions
# =============================================================================

def open_browser(url: str) -> bool:
    """Open URL in default browser. Returns success status."""
    try:
        return webbrowser.open(url)
    except Exception:
        return False


def prompt_for_code() -> str:
    """Prompt user for authentication code."""
    while True:
        print("Please enter the 6-digit code displayed in your browser to continue: ",
              end='', file=sys.stderr, flush=True)
        code = input().strip()
        if re.fullmatch(r'\d{6}', code):
            return code
        print("Invalid input: code must be a 6-digit number, please retry.",
              file=sys.stderr)


def download_certificate(url: str, timeout: int = 30) -> dict:
    """Download certificate from signing service."""
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"HTTP {response.status}")
            return json.loads(response.read().decode('utf-8'))
    except HTTPError as e:
        raise RuntimeError(f"Certificate download failed (HTTP {e.code})")
    except URLError as e:
        raise RuntimeError(f"Connection failed: {e.reason}")


# =============================================================================
# SSH Agent functions
# =============================================================================

def is_ssh_agent_running() -> bool:
    """
    Check if ssh-agent is running and accessible.

    Exit code 0 = keys listed, agent running
    Exit code 1 = no keys but agent running
    Other = agent not running
    """
    try:
        result = subprocess.run(
            ['ssh-add', '-l'],
            capture_output=True
        )
        # Exit 0 = keys listed, Exit 1 = no keys but agent running
        return result.returncode in (0, 1)
    except FileNotFoundError:
        return False


def is_key_in_ssh_agent(private_key_path: Path) -> bool:
    """
    Check if private key is already in ssh-agent.
    """
    env = os.environ.copy()

    # Get fingerprint of the key
    result = subprocess.run(
        ['ssh-keygen', '-lf', str(private_key_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
    )

    # Something failed, maybe wrong path?
    if result.returncode != 0:
        return False

    # ssh-keygen output format:
    # "<bits> <fingerprint> <comment>"
    fingerprint = result.stdout.split()[1]

    # List keys currently in the agent
    agent_keys = subprocess.run(
        ['ssh-add', '-l'],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
    )

    # Agent has no keys
    if agent_keys.returncode != 0:
        return False

    # Check if agent has the key fingerprint
    return fingerprint in agent_keys.stdout


def add_key_to_ssh_agent(private_key_path: Path) -> bool:
    """
    Add private key to ssh-agent.

    The adjacent certificate (-cert.pub) is automatically loaded by ssh-add.
    """
    env = os.environ.copy()
    env['SSH_ASKPASS'] = ''
    env['SSH_ASKPASS_REQUIRE'] = 'never'

    result = subprocess.run(
        ['ssh-add', str(private_key_path)],
        stdin=sys.stdin,
        capture_output=True,
        env=env
    )
    return result.returncode == 0


# =============================================================================
# Windows-specific functions (Pageant/PPK integration)
# =============================================================================

def find_executable_windows(name: str, common_paths: list) -> Optional[str]:
    """Find executable in PATH or common installation locations."""
    # Check PATH first
    path = shutil.which(name)
    if path:
        return path

    # Check common locations
    for p in common_paths:
        if os.path.isfile(p):
            return p

    return None


def find_winscp() -> Optional[str]:
    """Find winscp.com executable on Windows."""
    paths = [
        r'C:\Program Files\WinSCP\winscp.com',
        r'C:\Program Files (x86)\WinSCP\winscp.com',
    ]
    return find_executable_windows('winscp.com', paths)


def find_pageant() -> Optional[str]:
    """Find pageant.exe on Windows."""
    paths = [
        r'C:\Program Files\PuTTY\pageant.exe',
        r'C:\Program Files (x86)\PuTTY\pageant.exe',
        r'C:\Program Files\WinSCP\PuTTY\pageant.exe',
        r'C:\Program Files (x86)\WinSCP\PuTTY\pageant.exe',
    ]
    return find_executable_windows('pageant.exe', paths)


def is_pageant_running() -> bool:
    """Check if Pageant is currently running (Windows only)."""
    if platform.system() != 'Windows':
        return False

    try:
        result = subprocess.run(
            ['tasklist', '/FI', 'IMAGENAME eq pageant.exe', '/NH'],
            capture_output=True,
        )
        # Decode with latin-1 to avoid encoding errors; tasklist may output
        # UTF-16 or a Windows codepage, but we only match ASCII 'pageant.exe'
        stdout = result.stdout.decode('latin-1')
        return 'pageant.exe' in stdout.lower()
    except Exception:
        return False


def create_ppk(winscp_path: str, private_key: Path, cert_path: Path, ppk_path: Path) -> bool:
    """Create PPK file with embedded certificate using WinSCP."""
    # Use forward slashes (POSIX format) - WinSCP has issues with backslashes in arguments
    result = subprocess.run(
        [
            winscp_path,
            '/keygen',
            private_key.as_posix(),
            f'/output={ppk_path.as_posix()}',
            f'/certificate={cert_path.as_posix()}',
        ],
        stdin=sys.stdin,
        stdout=sys.stderr,
        stderr=sys.stderr,
    )
    return result.returncode == 0


def add_key_to_pageant(pageant_path: str, ppk_path: Path) -> bool:
    """Add PPK key to running Pageant agent."""
    result = subprocess.run(
        [pageant_path, ppk_path.as_posix()],
        stdin=sys.stdin,
        stdout=sys.stderr,
        stderr=sys.stderr,
    )
    return result.returncode == 0


def create_cert_ppk(config: Config) -> None:
    """
    Create a PPK file with embedded certificate using WinSCP.

    Skipped on non-Windows, when --no-ppk is set, or when private key is missing
    (for .pub input). For PPK input flow, WinSCP is required and failure raises.
    For .pub input flow, failure is non-fatal (graceful degradation).
    """
    if platform.system() != 'Windows' or not config.create_ppk:
        return

    winscp_path = find_winscp()
    if not winscp_path:
        if config.is_ppk:
            raise RuntimeError("WinSCP is required for PPK key flow but was not found")
        log_warning("WinSCP not found, skipping PPK creation", config)
        return

    if not config.is_ppk and not config.private_key_path.exists():
        return

    # For PPK input, WinSCP takes the PPK itself; for OpenSSH input, the private key
    keygen_input = config.public_key_path if config.is_ppk else config.private_key_path
    if not create_ppk(winscp_path, keygen_input, config.cert_path, config.ppk_path):
        log_warning("Failed to create PPK file", config)
        return

    log(f"Certificate written: {config.ppk_path}", config)


# =============================================================================
# Status functions
# =============================================================================

def get_openssh_version() -> Optional[str]:
    """Get OpenSSH version string."""
    try:
        ssh_path = shutil.which('ssh')
        if ssh_path:
            result = subprocess.run(
                [ssh_path, '-V'],
                capture_output=True,
                text=True,
                errors='replace',
                timeout=5
            )
            # ssh -V outputs to stderr
            output = result.stderr.strip() or result.stdout.strip()
            # Extract just the version part (e.g., "OpenSSH_9.6p1")
            if output:
                return output.split(',')[0].split()[0] if ',' in output else output.split()[0]
    except Exception:
        pass
    return None


def check_endpoint_reachable(url: str, timeout: int = 5) -> bool:
    """Check if the authentication endpoint is reachable."""
    try:
        req = urllib.request.Request(url, method='HEAD')
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status < 400
    except Exception:
        # Try GET if HEAD fails
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.status < 400
        except Exception:
            return False


def _format_cert_status(info: CertificateInfo) -> str:
    """Format certificate validity info as a status string."""
    if info.error:
        return f"ERROR ({info.error})"
    elif info.expiry:
        status = "valid until" if info.is_valid else "EXPIRED"
        expiry_str = info.expiry.strftime('%Y-%m-%d %H:%M:%S')
        return f"{status} {expiry_str}"
    else:
        return "unknown status"


def _find_associated_certs(key_path: Path) -> list:
    """
    Find certificate files associated with a key file.

    For .pub keys: looks for <name>-cert.pub
    For .ppk keys: looks for <name>-cert.ppk and <name>-cert.pub
    Returns list of (cert_path, CertificateInfo) tuples for certs that exist.
    """
    results = []
    if key_path.suffix == '.ppk':
        stem = key_path.stem  # e.g. "id_ed25519"
        parent = key_path.parent

        # Check for cert-embedded PPK
        ppk_cert = parent / f"{stem}-cert.ppk"
        if ppk_cert.exists():
            results.append((ppk_cert, check_ppk_certificate_validity(ppk_cert)))

        # Also check for OpenSSH cert
        pub_cert = parent / f"{stem}-cert.pub"
        if pub_cert.exists():
            results.append((pub_cert, check_certificate_validity(pub_cert)))

        # The PPK itself might contain an embedded certificate
        if not results and key_path.exists():
            try:
                key_type, _ = parse_ppk_header(key_path)
                if '-cert' in key_type:
                    results.append((key_path, check_ppk_certificate_validity(key_path)))
            except Exception:
                pass
    else:
        # .pub key
        private_name = key_path.stem  # e.g. "id_ed25519"
        cert_path = key_path.parent / f"{private_name}-cert.pub"
        if cert_path.exists():
            results.append((cert_path, check_certificate_validity(cert_path)))

    return results


def show_status(key_path: Optional[Path] = None) -> None:
    """Show system status: keys, tools, agents, and endpoint connectivity."""
    is_windows = platform.system() == 'Windows'
    ssh_dir = Path.home() / '.ssh'

    print("Status:", file=sys.stderr)
    print(file=sys.stderr)

    # Specified key (from command line)
    if key_path is not None:
        print("Specified Key:", file=sys.stderr)
        if key_path.exists():
            print(f"  {key_path}", file=sys.stderr)
            associated = _find_associated_certs(key_path)
            if associated:
                for cert, info in associated:
                    print(f"    cert: {cert}: {_format_cert_status(info)}", file=sys.stderr)
            else:
                print(f"    cert: (no certificate found)", file=sys.stderr)
        else:
            print(f"  {key_path}: NOT FOUND", file=sys.stderr)
        print(file=sys.stderr)

    # SSH Keys in ~/.ssh
    print("SSH Keys (~/.ssh):", file=sys.stderr)
    pub_keys = list(ssh_dir.glob('*.pub')) if ssh_dir.exists() else []
    # Filter out certificate files for the keys section
    pub_keys = [k for k in pub_keys if not k.name.endswith('-cert.pub')]
    ppk_keys = list(ssh_dir.glob('*.ppk')) if ssh_dir.exists() else []
    ppk_keys = [k for k in ppk_keys if not k.name.endswith('-cert.ppk')]
    all_keys = sorted(pub_keys + ppk_keys)
    if all_keys:
        for key in all_keys:
            print(f"  {key}", file=sys.stderr)
    else:
        print("  (none found)", file=sys.stderr)
    print(file=sys.stderr)

    # Certificates in ~/.ssh
    print("Certificates (~/.ssh):", file=sys.stderr)
    cert_files = list(ssh_dir.glob('*-cert.pub')) if ssh_dir.exists() else []
    cert_ppk_files = list(ssh_dir.glob('*-cert.ppk')) if ssh_dir.exists() else []
    all_certs = sorted(cert_files + cert_ppk_files)
    if all_certs:
        for cert in all_certs:
            if cert.suffix == '.ppk':
                info = check_ppk_certificate_validity(cert)
            else:
                info = check_certificate_validity(cert)
            print(f"  {cert}: {_format_cert_status(info)}", file=sys.stderr)
    else:
        print("  (none found)", file=sys.stderr)
    print(file=sys.stderr)

    # Tools
    print("Tools:", file=sys.stderr)
    ssh_keygen_path = shutil.which('ssh-keygen')
    ssh_add_path = shutil.which('ssh-add')
    openssh_ver = get_openssh_version()
    ver_str = f" ({openssh_ver})" if openssh_ver else ""

    print(f"  ssh-keygen: {ssh_keygen_path or 'not found'}{ver_str if ssh_keygen_path else ''}", file=sys.stderr)
    print(f"  ssh-add: {ssh_add_path or 'not found'}{ver_str if ssh_add_path else ''}", file=sys.stderr)

    if is_windows:
        winscp_path = find_winscp()
        pageant_path = find_pageant()
        print(f"  winscp.com: {winscp_path or 'not found'}", file=sys.stderr)
        print(f"  pageant.exe: {pageant_path or 'not found'}", file=sys.stderr)
    print(file=sys.stderr)

    # Agents
    print("Agents:", file=sys.stderr)
    ssh_agent_status = "running" if is_ssh_agent_running() else "not running"
    print(f"  ssh-agent: {ssh_agent_status}", file=sys.stderr)
    if is_windows:
        pageant_status = "running" if is_pageant_running() else "not running"
        print(f"  Pageant: {pageant_status}", file=sys.stderr)
    print(file=sys.stderr)

    # Authentication Endpoint
    print("Authentication Endpoint:", file=sys.stderr)
    endpoint_ok = check_endpoint_reachable(BASE_URL)
    status = "OK" if endpoint_ok else "unreachable"
    print(f"  {BASE_URL}: {status}", file=sys.stderr)


# =============================================================================
# Main workflow steps
# =============================================================================

def check_existing_certificate(config: Config) -> CertificateInfo:
    """Check status of the existing certificate, if any."""
    if config.is_ppk:
        return check_ppk_certificate_validity(config.ppk_path)
    return check_certificate_validity(config.cert_path)


def compute_key_fingerprint(config: Config) -> str:
    """Compute the SHA-256 fingerprint of the input key."""
    if config.is_ppk:
        key_bytes = parse_ppk_public_key(config.public_key_path)
        return compute_fingerprint_from_bytes(key_bytes)
    return compute_fingerprint(config.public_key_path)


def log_key_info(config: Config) -> None:
    """Log key paths and warn about features disabled by missing private key."""
    if not config.is_ppk and not config.private_key_path.exists():
        disabled = "ssh-agent and PPK creation" if platform.system() == 'Windows' else "ssh-agent"
        log(f"Private key not found — {disabled} disabled", config)

    label = "PPK key" if config.is_ppk else "Public key to sign"
    log(f"{label}: {config.public_key_path}", config)
    target_path = config.ppk_path if config.is_ppk else config.cert_path
    target_label = "Certificate PPK" if config.is_ppk else "Certificate"
    log(f"{target_label}: {target_path}", config)


def authenticate_and_download(config: Config, fingerprint: str) -> str:
    """
    Browser auth flow + certificate download.

    Returns the certificate data string.
    """
    payload = create_payload(fingerprint, config.username)
    login_url = f"{BASE_URL}/login?certSign={payload}&sshCli=true"

    print("Please log in to sign the public key:", file=sys.stderr)
    print(file=sys.stderr)
    print(login_url, file=sys.stderr)
    print(file=sys.stderr)

    open_browser(login_url)
    code = prompt_for_code()

    download_url = f"{BASE_URL}/api/certificate/download/{payload}?code={code}"
    response = download_certificate(download_url)

    if not response.get('success'):
        key_name = config.public_key_path
        raise RuntimeError(
            "Certificate signing was not successful. The three most likely causes are:\n"
            f" 1. The public key you are attempting to sign ({key_name}) has not been added to MyCSC. Please add it first.\n"
            " 2. You did not log in successfully. Please run this script again and log in via the provided link.\n"
            " 3. You entered an incorrect 6-digit code after logging in. Please run this script again to retry."
        )

    return response['data']


def write_certificate(config: Config, cert_data: str) -> None:
    """Write the OpenSSH certificate file and log its status."""
    config.cert_path.write_bytes(cert_data.encode('utf-8'))
    config.cert_path.chmod(0o600)

    new_cert_info = check_certificate_validity(config.cert_path)
    if new_cert_info.expiry:
        log(f"Certificate signed, {_format_cert_status(new_cert_info)}", config)

    if not config.is_ppk:
        log(f"Certificate written: {config.cert_path}", config)


def maybe_add_to_ssh_agent(config: Config) -> None:
    """
    Add private key + certificate to ssh-agent if applicable.

    Skipped for PPK input (no OpenSSH private key), when private key is
    missing, or when agent mode excludes ssh-agent.
    """
    if config.is_ppk or config.agent_mode in ('pageant', 'none'):
        return
    if not config.private_key_path.exists():
        return

    if not is_ssh_agent_running():
        log_warning("ssh-agent not running, key not added", config)
        return

    if is_key_in_ssh_agent(config.private_key_path):
        log(f"Not adding private key; ssh-agent already has it: {config.private_key_path}", config, verbose_only=True)
        return

    log(f"Adding private key to ssh-agent: {config.private_key_path}", config, verbose_only=True)
    if add_key_to_ssh_agent(config.private_key_path):
        log("Certificate added to ssh-agent", config)
    else:
        raise RuntimeError("Failed to add private key to ssh-agent")


def maybe_load_into_pageant(config: Config) -> None:
    """
    Add the cert-embedded PPK to a running Pageant instance.

    Skipped when agent mode excludes Pageant or PPK file doesn't exist.
    Non-fatal: logs warnings on failure instead of raising.
    """
    if config.agent_mode in ('ssh', 'none'):
        return
    if not config.ppk_path.exists():
        return

    if not is_pageant_running():
        log_warning("Pageant not running, skipping key addition", config)
        return

    pageant_path = find_pageant()
    if not pageant_path:
        log_warning("Pageant not found, skipping key addition", config)
        return

    if not add_key_to_pageant(pageant_path, config.ppk_path):
        log_warning("Failed to add key to Pageant", config)
    else:
        log("Certificate added to Pageant", config)


def cleanup_intermediate_cert(config: Config) -> None:
    """Remove the intermediate -cert.pub for PPK input flow (only -cert.ppk is needed)."""
    if config.is_ppk and config.cert_path.exists():
        config.cert_path.unlink()


# =============================================================================
# CLI argument parsing
# =============================================================================

def parse_args() -> tuple:
    """Parse command-line arguments. Returns (config, status_mode)."""
    is_windows = platform.system() == 'Windows'

    parser = argparse.ArgumentParser(
        description='Download a signed SSH certificate from the signing service.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -u myusername
  %(prog)s -u myusername ~/.ssh/id_rsa.pub
  %(prog)s -u myusername -r    # Force refresh
  %(prog)s -u myusername -a none    # Skip agent
  %(prog)s -S    # Show status
  %(prog)s -S path/to/key.ppk    # Show status including specified key
'''
    )

    parser.add_argument('-u', '--username',
                        help='Username (required for certificate operations)')
    parser.add_argument('-s', '--silent', action='store_true',
                        help='Silent mode (minimal output)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose mode (detailed output)')
    parser.add_argument('-r', '--refresh', action='store_true',
                        help='Refresh certificate even if still valid')
    parser.add_argument('-S', '--status', action='store_true',
                        help='Show status of keys, tools, agents, and endpoint')

    if is_windows:
        parser.add_argument('-a', '--agent', default='both',
                            choices=['both', 'pageant', 'ssh', 'none'],
                            help="Agent mode (default: both)")
        parser.add_argument('-p', '--no-ppk', action='store_true',
                            help="Skip PPK file creation (Windows only)")
    else:
        parser.add_argument('-a', '--agent', default='ssh',
                            choices=['ssh', 'none'],
                            help="Agent mode (default: ssh)")

    parser.add_argument('public_key', nargs='?', type=Path,
                        help='Path to SSH public key (.pub) or PuTTY key (.ppk)')

    args = parser.parse_args()

    # Status mode doesn't need username or other validation
    if args.status:
        key_path = None
        if args.public_key:
            key_path = args.public_key.expanduser().resolve()
        return key_path, True

    # For certificate operations, username is required
    if not args.username:
        parser.error("the following arguments are required: -u/--username")

    # Validate agent mode for non-Windows
    if not is_windows and args.agent in ('pageant', 'both'):
        parser.error("Pageant is only available on Windows. Use 'ssh' or 'none'")

    # Find default public key if not specified
    if args.public_key:
        public_key_path = args.public_key.expanduser().resolve()
    else:
        public_key_path = find_default_public_key()

    if is_windows and getattr(args, 'no_ppk', False) and public_key_path.suffix == '.ppk':
        parser.error("--no-ppk cannot be used with a .ppk input key")

    config = Config(
        username=args.username,
        public_key_path=public_key_path,
        agent_mode=args.agent,
        silent=args.silent,
        verbose=args.verbose,
        refresh=args.refresh,
        create_ppk=not getattr(args, 'no_ppk', False),
    )
    return config, False


def main() -> int:
    """Entry point — orchestrates the full certificate signing workflow."""
    try:
        config, status_mode = parse_args()

        if status_mode:
            show_status(config)
            return 0

        validate_username(config.username)
        if config.public_key_path.suffix not in ('.pub', '.ppk'):
            raise ValueError("Key path must end in .pub or .ppk")

        log_key_info(config)
        cert_info = check_existing_certificate(config)

        if cert_info.error:
            log_warning(f"Could not check existing certificate: {cert_info.error}", config)
        elif cert_info.is_valid and not config.refresh:
            log(f"Certificate {_format_cert_status(cert_info)}", config)
            return 0
        elif cert_info.is_valid and config.refresh:
            log(f"Certificate {_format_cert_status(cert_info)}, refreshing anyway", config)

        fingerprint = compute_key_fingerprint(config)
        cert_data = authenticate_and_download(config, fingerprint)
        write_certificate(config, cert_data)
        maybe_add_to_ssh_agent(config)
        create_cert_ppk(config)
        maybe_load_into_pageant(config)
        cleanup_intermediate_cert(config)
        return 0
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
