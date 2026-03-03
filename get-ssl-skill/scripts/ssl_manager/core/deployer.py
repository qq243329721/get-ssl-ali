"""SSH-based certificate deployment using paramiko."""

from __future__ import annotations

from datetime import datetime
from pathlib import PurePosixPath

import paramiko

from ssl_manager.models import ServerConfig
from ssl_manager.utils.logger import log


class Deployer:
    """Deploy certificates to remote servers via SSH/SFTP."""

    def __init__(self, backup: bool = True):
        self._backup = backup

    def deploy(
        self,
        server: ServerConfig,
        local_cert: str,
        local_key: str,
    ) -> None:
        """Deploy certificate files to a remote server.

        Flow:
        1. SSH connect
        2. Backup old certs (if enabled)
        3. SFTP upload new cert and key
        4. Set file permissions (cert: 644, key: 600)
        5. nginx -t to validate config
        6. Reload nginx (rollback if validation fails)

        Args:
            server: Target server config.
            local_cert: Local path to certificate file.
            local_key: Local path to private key file.

        Raises:
            RuntimeError: If deployment fails critically.
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            log.info(f"Connecting to {server.user}@{server.host}:{server.port}")
            ssh.connect(
                hostname=server.host,
                port=server.port,
                username=server.user,
                password=server.password,
                timeout=30,
            )

            sftp = ssh.open_sftp()

            # Ensure remote directories exist
            self._ensure_remote_dir(ssh, str(PurePosixPath(server.cert_path).parent))
            self._ensure_remote_dir(ssh, str(PurePosixPath(server.key_path).parent))

            # Backup old certs
            backup_suffix = None
            if self._backup:
                backup_suffix = self._backup_certs(ssh, sftp, server)

            # Upload new cert and key
            log.info(f"Uploading certificate to {server.cert_path}")
            sftp.put(local_cert, server.cert_path)
            log.info(f"Uploading private key to {server.key_path}")
            sftp.put(local_key, server.key_path)

            # Set permissions
            self._exec(ssh, f"chmod 644 {server.cert_path}")
            self._exec(ssh, f"chmod 600 {server.key_path}")

            # Validate and reload nginx
            # The reload_cmd typically includes "nginx -t && nginx -s reload",
            # so we use it directly instead of hardcoding a separate validation step
            log.info(f"Executing: {server.reload_cmd}")
            exit_code, stdout, stderr = self._exec(ssh, server.reload_cmd)

            if exit_code != 0:
                log.error(f"Reload failed: {stderr}")
                if backup_suffix:
                    log.warn("Rolling back to previous certificates")
                    self._rollback(ssh, server, backup_suffix)
                raise RuntimeError(
                    f"nginx reload failed on {server.host}: {stderr}"
                )

            log.success(f"Certificate deployed successfully to {server.host}")

        finally:
            ssh.close()

    def _backup_certs(
        self, ssh: paramiko.SSHClient, sftp: paramiko.SFTPClient, server: ServerConfig
    ) -> str | None:
        """Backup existing certificate files.

        Returns:
            Backup suffix string, or None if no files to backup.
        """
        suffix = datetime.now().strftime(".bak.%Y%m%d%H%M%S")
        backed_up = False

        for path in [server.cert_path, server.key_path]:
            try:
                sftp.stat(path)
                backup_path = path + suffix
                self._exec(ssh, f"cp -f {path} {backup_path}")
                log.info(f"Backed up {path} -> {backup_path}")
                backed_up = True
            except FileNotFoundError:
                log.debug(f"No existing file to backup: {path}")

        return suffix if backed_up else None

    def _rollback(
        self, ssh: paramiko.SSHClient, server: ServerConfig, suffix: str
    ) -> None:
        """Restore certificates from backup."""
        for path in [server.cert_path, server.key_path]:
            backup_path = path + suffix
            try:
                self._exec(ssh, f"cp -f {backup_path} {path}")
                log.info(f"Restored {backup_path} -> {path}")
            except Exception as e:
                log.error(f"Rollback failed for {path}: {e}")

    def _ensure_remote_dir(self, ssh: paramiko.SSHClient, path: str) -> None:
        """Ensure remote directory exists."""
        self._exec(ssh, f"mkdir -p {path}")

    @staticmethod
    def _exec(
        ssh: paramiko.SSHClient, cmd: str
    ) -> tuple[int, str, str]:
        """Execute a remote command and return (exit_code, stdout, stderr)."""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return exit_code, out, err
