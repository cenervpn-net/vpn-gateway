#!/usr/bin/env python3
"""
CenterVPN Gateway Release Verification Module

This module provides cryptographic verification of software releases before deployment.
It verifies:
1. GPG signature of the manifest
2. Git commit hash matches
3. File checksums (SHA-256) match the manifest
4. Git tag signature (optional)

Usage:
    from verify_release import ReleaseVerifier
    
    verifier = ReleaseVerifier(trusted_keys_dir="/path/to/keys")
    result = verifier.verify_release(manifest_content, manifest_signature, expected_commit)
"""

import hashlib
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Default paths
DEFAULT_TRUSTED_KEYS_DIR = "/home/ubuntu/wg-manager/trusted_keys"
DEFAULT_GATEWAY_API_DIR = "/home/ubuntu/wg-manager/gateway_api"
DEFAULT_REPO_DIR = "/home/ubuntu/wg-manager"


@dataclass
class VerificationResult:
    """Result of release verification"""
    success: bool
    signature_valid: bool = False
    commit_hash_valid: bool = False
    files_valid: bool = False
    tag_signature_valid: bool = False
    
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    verified_files: List[str] = field(default_factory=list)
    failed_files: List[str] = field(default_factory=list)
    
    gpg_key_id: Optional[str] = None
    gpg_key_owner: Optional[str] = None
    manifest_version: Optional[str] = None
    manifest_commit: Optional[str] = None
    
    verified_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "signature_valid": self.signature_valid,
            "commit_hash_valid": self.commit_hash_valid,
            "files_valid": self.files_valid,
            "tag_signature_valid": self.tag_signature_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "verified_files": self.verified_files,
            "failed_files": self.failed_files,
            "gpg_key_id": self.gpg_key_id,
            "gpg_key_owner": self.gpg_key_owner,
            "manifest_version": self.manifest_version,
            "manifest_commit": self.manifest_commit,
            "verified_at": self.verified_at.isoformat(),
        }
    
    def to_log(self) -> str:
        """Generate log-friendly string"""
        lines = [
            f"=== Release Verification Result ===",
            f"Overall: {'PASSED' if self.success else 'FAILED'}",
            f"Signature: {'✓' if self.signature_valid else '✗'}",
            f"Commit Hash: {'✓' if self.commit_hash_valid else '✗'}",
            f"File Checksums: {'✓' if self.files_valid else '✗'}",
            f"Tag Signature: {'✓' if self.tag_signature_valid else '○ (not checked)'}",
        ]
        
        if self.gpg_key_id:
            lines.append(f"GPG Key: {self.gpg_key_id}")
        if self.manifest_version:
            lines.append(f"Version: {self.manifest_version}")
        if self.manifest_commit:
            lines.append(f"Commit: {self.manifest_commit}")
        
        if self.errors:
            lines.append(f"\nErrors:")
            for err in self.errors:
                lines.append(f"  - {err}")
        
        if self.warnings:
            lines.append(f"\nWarnings:")
            for warn in self.warnings:
                lines.append(f"  - {warn}")
        
        if self.failed_files:
            lines.append(f"\nFailed Files:")
            for f in self.failed_files:
                lines.append(f"  - {f}")
        
        return "\n".join(lines)


class ReleaseVerifier:
    """
    Verifies software releases using cryptographic signatures.
    
    Security layers:
    1. GPG signature verification of manifest
    2. Git commit hash verification
    3. File checksum verification
    4. Git tag signature verification (optional)
    """
    
    def __init__(
        self,
        trusted_keys_dir: str = DEFAULT_TRUSTED_KEYS_DIR,
        gateway_api_dir: str = DEFAULT_GATEWAY_API_DIR,
        repo_dir: str = DEFAULT_REPO_DIR,
    ):
        self.trusted_keys_dir = Path(trusted_keys_dir)
        self.gateway_api_dir = Path(gateway_api_dir)
        self.repo_dir = Path(repo_dir)
        
        # Ensure trusted keys directory exists
        self.trusted_keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Import any trusted keys found in the directory
        self._import_trusted_keys()
    
    def _import_trusted_keys(self) -> None:
        """Import all GPG keys from trusted_keys_dir into GPG keyring"""
        for key_file in self.trusted_keys_dir.glob("*.asc"):
            try:
                result = subprocess.run(
                    ["gpg", "--import", str(key_file)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    logger.info(f"Imported trusted key: {key_file.name}")
                else:
                    logger.warning(f"Failed to import key {key_file.name}: {result.stderr}")
            except Exception as e:
                logger.warning(f"Error importing key {key_file.name}: {e}")
    
    def add_trusted_key(self, public_key_armor: str, key_id: str) -> bool:
        """
        Add a new trusted GPG public key.
        
        Args:
            public_key_armor: ASCII armored public key
            key_id: GPG key ID (fingerprint)
        
        Returns:
            True if key was added successfully
        """
        key_file = self.trusted_keys_dir / f"{key_id}.asc"
        
        try:
            # Save key to file
            with open(key_file, "w") as f:
                f.write(public_key_armor)
            
            # Import into GPG keyring
            result = subprocess.run(
                ["gpg", "--import", str(key_file)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode == 0:
                logger.info(f"Added trusted key: {key_id}")
                return True
            else:
                logger.error(f"Failed to import key: {result.stderr}")
                key_file.unlink(missing_ok=True)
                return False
                
        except Exception as e:
            logger.error(f"Error adding trusted key: {e}")
            return False
    
    def verify_gpg_signature(
        self,
        manifest_content: str,
        manifest_signature: str,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Verify GPG signature of manifest.
        
        Args:
            manifest_content: The manifest JSON content
            manifest_signature: Detached GPG signature (ASCII armored)
        
        Returns:
            Tuple of (is_valid, key_id, key_owner)
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_file = Path(tmpdir) / "manifest.json"
            sig_file = Path(tmpdir) / "manifest.json.sig"
            
            # Write files
            manifest_file.write_text(manifest_content)
            sig_file.write_text(manifest_signature)
            
            # Verify signature
            result = subprocess.run(
                [
                    "gpg",
                    "--verify",
                    "--status-fd", "1",
                    str(sig_file),
                    str(manifest_file),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            # Parse GPG output
            key_id = None
            key_owner = None
            is_valid = False
            
            for line in result.stdout.split("\n") + result.stderr.split("\n"):
                if "GOODSIG" in line:
                    is_valid = True
                    parts = line.split()
                    if len(parts) >= 3:
                        key_id = parts[2]
                        key_owner = " ".join(parts[3:]) if len(parts) > 3 else None
                elif "VALIDSIG" in line:
                    is_valid = True
                    parts = line.split()
                    if len(parts) >= 3:
                        key_id = key_id or parts[2]
                elif "BADSIG" in line or "ERRSIG" in line:
                    is_valid = False
                elif "using RSA key" in line or "using DSA key" in line:
                    # Extract key ID from human-readable output
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "key":
                            key_id = key_id or parts[i + 1] if i + 1 < len(parts) else None
            
            return is_valid, key_id, key_owner
    
    def verify_commit_hash(
        self,
        expected_hash: str,
        git_tag: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Verify that the local repository is at the expected commit.
        
        Args:
            expected_hash: Expected git commit hash
            git_tag: Optional git tag to checkout
        
        Returns:
            Tuple of (is_valid, actual_hash)
        """
        try:
            # Get current commit hash
            result = subprocess.run(
                ["git", "-C", str(self.repo_dir), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            actual_hash = result.stdout.strip()
            
            # Compare (allow prefix match for short hashes)
            is_valid = (
                actual_hash == expected_hash or
                actual_hash.startswith(expected_hash) or
                expected_hash.startswith(actual_hash)
            )
            
            return is_valid, actual_hash
            
        except Exception as e:
            logger.error(f"Error verifying commit hash: {e}")
            return False, ""
    
    def verify_file_checksums(
        self,
        manifest: dict,
    ) -> Tuple[bool, List[str], List[str]]:
        """
        Verify file checksums match the manifest.
        
        Args:
            manifest: Parsed manifest dict with "files" section
        
        Returns:
            Tuple of (all_valid, verified_files, failed_files)
        """
        verified_files = []
        failed_files = []
        
        files = manifest.get("files", {})
        
        for filename, file_info in files.items():
            expected_checksum = file_info.get("sha256")
            if not expected_checksum:
                failed_files.append(f"{filename} (no checksum in manifest)")
                continue
            
            filepath = self.gateway_api_dir / filename
            
            if not filepath.exists():
                failed_files.append(f"{filename} (file not found)")
                continue
            
            # Calculate actual checksum
            actual_checksum = self._sha256_file(filepath)
            
            if actual_checksum == expected_checksum:
                verified_files.append(filename)
            else:
                failed_files.append(f"{filename} (checksum mismatch)")
                logger.warning(
                    f"Checksum mismatch for {filename}: "
                    f"expected {expected_checksum[:16]}..., got {actual_checksum[:16]}..."
                )
        
        return len(failed_files) == 0, verified_files, failed_files
    
    def verify_git_tag_signature(self, tag: str) -> bool:
        """
        Verify the GPG signature on a git tag.
        
        Args:
            tag: Git tag name (e.g., "v1.2.0")
        
        Returns:
            True if tag signature is valid
        """
        try:
            result = subprocess.run(
                ["git", "-C", str(self.repo_dir), "tag", "-v", tag],
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.warning(f"Error verifying git tag signature: {e}")
            return False
    
    def _sha256_file(self, filepath: Path) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def verify_release(
        self,
        manifest_content: str,
        manifest_signature: str,
        expected_commit: Optional[str] = None,
        expected_tag: Optional[str] = None,
        skip_file_check: bool = False,
    ) -> VerificationResult:
        """
        Perform full release verification.
        
        Args:
            manifest_content: JSON manifest content
            manifest_signature: GPG signature of manifest
            expected_commit: Expected git commit hash (from backend DB)
            expected_tag: Expected git tag (optional)
            skip_file_check: Skip file checksum verification
        
        Returns:
            VerificationResult with all verification details
        """
        result = VerificationResult(success=False)
        
        # Step 1: Verify GPG signature
        logger.info("Verifying GPG signature...")
        sig_valid, key_id, key_owner = self.verify_gpg_signature(
            manifest_content, manifest_signature
        )
        result.signature_valid = sig_valid
        result.gpg_key_id = key_id
        result.gpg_key_owner = key_owner
        
        if not sig_valid:
            result.errors.append("GPG signature verification failed")
            logger.error("GPG signature verification failed!")
            return result
        
        logger.info(f"GPG signature valid (key: {key_id})")
        
        # Parse manifest
        try:
            manifest = json.loads(manifest_content)
            result.manifest_version = manifest.get("version")
            result.manifest_commit = manifest.get("git_commit")
        except json.JSONDecodeError as e:
            result.errors.append(f"Failed to parse manifest: {e}")
            return result
        
        # Step 2: Verify commit hash
        if expected_commit or result.manifest_commit:
            logger.info("Verifying commit hash...")
            check_commit = expected_commit or result.manifest_commit
            commit_valid, actual_commit = self.verify_commit_hash(check_commit)
            result.commit_hash_valid = commit_valid
            
            if not commit_valid:
                result.errors.append(
                    f"Commit hash mismatch: expected {check_commit[:12]}..., "
                    f"got {actual_commit[:12]}..."
                )
                logger.error("Commit hash verification failed!")
                return result
            
            logger.info(f"Commit hash valid: {actual_commit[:12]}...")
        else:
            result.warnings.append("No commit hash to verify")
            result.commit_hash_valid = True  # Pass if nothing to check
        
        # Step 3: Verify file checksums
        if not skip_file_check:
            logger.info("Verifying file checksums...")
            files_valid, verified, failed = self.verify_file_checksums(manifest)
            result.files_valid = files_valid
            result.verified_files = verified
            result.failed_files = failed
            
            if not files_valid:
                result.errors.append(f"File checksum verification failed: {len(failed)} files")
                logger.error("File checksum verification failed!")
                return result
            
            logger.info(f"File checksums valid: {len(verified)} files verified")
        else:
            result.files_valid = True
            result.warnings.append("File checksum verification skipped")
        
        # Step 4: Verify git tag signature (optional)
        tag = expected_tag or manifest.get("git_tag")
        if tag:
            logger.info(f"Verifying git tag signature: {tag}")
            result.tag_signature_valid = self.verify_git_tag_signature(tag)
            if not result.tag_signature_valid:
                result.warnings.append(f"Git tag {tag} signature not verified")
        
        # All checks passed!
        result.success = True
        logger.info("All verification checks passed!")
        
        return result


def verify_before_deploy(
    manifest_content: str,
    manifest_signature: str,
    expected_commit: str,
    trusted_key_armor: Optional[str] = None,
    trusted_key_id: Optional[str] = None,
) -> VerificationResult:
    """
    Convenience function to verify a release before deployment.
    
    This is called by the deployment service before applying any updates.
    
    Args:
        manifest_content: JSON manifest from backend
        manifest_signature: GPG signature from backend
        expected_commit: Commit hash from backend DB
        trusted_key_armor: Optional GPG public key to add
        trusted_key_id: Key ID if adding a new key
    
    Returns:
        VerificationResult
    """
    verifier = ReleaseVerifier()
    
    # Add trusted key if provided
    if trusted_key_armor and trusted_key_id:
        verifier.add_trusted_key(trusted_key_armor, trusted_key_id)
    
    return verifier.verify_release(
        manifest_content=manifest_content,
        manifest_signature=manifest_signature,
        expected_commit=expected_commit,
    )


if __name__ == "__main__":
    # Example usage / test
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 3:
        print("Usage: python verify_release.py <manifest.json> <manifest.json.sig> [commit_hash]")
        sys.exit(1)
    
    manifest_file = sys.argv[1]
    sig_file = sys.argv[2]
    commit_hash = sys.argv[3] if len(sys.argv) > 3 else None
    
    with open(manifest_file) as f:
        manifest_content = f.read()
    
    with open(sig_file) as f:
        manifest_signature = f.read()
    
    verifier = ReleaseVerifier()
    result = verifier.verify_release(
        manifest_content=manifest_content,
        manifest_signature=manifest_signature,
        expected_commit=commit_hash,
    )
    
    print(result.to_log())
    sys.exit(0 if result.success else 1)
