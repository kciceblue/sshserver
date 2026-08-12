from pathlib import Path
import hashlib
import os
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GUIDE = (ROOT / "docs" / "SELF-HOSTING.md").read_text(encoding="utf-8")
PACKAGING = (ROOT / "packaging" / "README.md").read_text(encoding="utf-8")
CLI = (ROOT / "runtime" / "internal" / "cli" / "cli.go").read_text(
    encoding="utf-8"
)
CONFIG = (ROOT / "runtime" / "internal" / "config" / "config.go").read_text(
    encoding="utf-8"
)
LIFECYCLE = (
    ROOT / "runtime" / "internal" / "deployment" / "lifecycle.go"
).read_text(encoding="utf-8")
SHELL_BLOCKS = re.findall(
    r"^[ \t]*```sh\n(.*?)^[ \t]*```[ \t]*$",
    GUIDE,
    flags=re.DOTALL | re.MULTILINE,
)


class SelfHostDocumentationTests(unittest.TestCase):
    def test_release_contract_links_the_self_host_surface(self) -> None:
        self.assertIn("[self-hosting guide](../docs/SELF-HOSTING.md)", PACKAGING)
        self.assertIn("cold backup/restore", PACKAGING)

    def test_guide_covers_both_install_paths_and_supported_targets(self) -> None:
        required = (
            "Fast path: install and enroll from the app",
            "Equivalent pinned one-line install",
            "Linux or macOS",
            "`amd64`/`x86_64`",
            "`arm64`/`aarch64`",
            "To add a second device in base mode",
            "Verify receipt",
            "no `sudo`",
            "active seven-day product preview or lifetime unlock",
            "release panel displays `v0.1.1`",
        )
        for statement in required:
            with self.subTest(statement=statement):
                self.assertIn(statement, GUIDE)

    def test_one_line_example_is_release_pinned_and_never_pipes_to_shell(self) -> None:
        self.assertIn(
            "https://kciceblue.github.io/sshserver/releases/v0.1.1/"
            "install-command.txt",
            GUIDE,
        )
        self.assertIn("printf '%s' \"$JAT_INSTALL_PROGRAM\" | wc -c", GUIDE)
        self.assertIn("= 5779", GUIDE)
        self.assertIn(
            "485f80db51a14b1001ee58f5ed3174090d22fa6bf00d8e3324b8e94e87210be6",
            GUIDE,
        )
        self.assertIn('/bin/sh -c "$JAT_INSTALL_PROGRAM" install-command.txt', GUIDE)
        self.assertNotIn('/bin/sh "$JAT_INSTALL_COMMAND"', GUIDE)
        for option in ("--disable", "--tlsv1.2", "--max-filesize 5779"):
            self.assertIn(option, GUIDE)
        self.assertIn("mktemp -d", GUIDE)
        self.assertIn("command -v sha256sum", GUIDE)
        self.assertIn("shasum -a 256", GUIDE)
        self.assertIn("PATH=/usr/bin:/bin", GUIDE)
        self.assertIn("LC_ALL=C", GUIDE)
        self.assertIn('JAT_INSTALL_BOOTSTRAP_ROOT="$(pwd -P)"', GUIDE)
        self.assertIn(
            '"$JAT_INSTALL_BOOTSTRAP_ROOT"/jat-install.*', GUIDE
        )
        self.assertIn('case "$JAT_INSTALL_COMMAND_DIR" in', GUIDE)
        self.assertIn("ulimit -c 0", GUIDE)
        self.assertIn("trap '' XFSZ", GUIDE)
        self.assertIn("ulimit -f 12", GUIDE)
        self.assertIn('exec 5< "$JAT_INSTALL_COMMAND"', GUIDE)
        self.assertIn('rm -f "$JAT_INSTALL_COMMAND"', GUIDE)
        self.assertIn('/bin/cat <&5', GUIDE)
        self.assertIn('JAT_INSTALL_PROGRAM=${JAT_INSTALL_WITH_SENTINEL%', GUIDE)
        self.assertIn('rmdir "$JAT_INSTALL_COMMAND_DIR"', GUIDE)
        shell_blocks = "\n".join(SHELL_BLOCKS)
        self.assertNotIn("rm -rf", shell_blocks)
        self.assertIsNone(
            re.search(
                r"curl[^\n]*(?:\n[^\n]*){0,2}\|\s*(?:/bin/)?sh",
                shell_blocks,
            )
        )
        self.assertIn("Unverified response bytes are never piped into a shell", PACKAGING)

    def test_installer_workspace_uses_the_physical_tmp_root(self) -> None:
        install_block = next(
            block
            for block in SHELL_BLOCKS
            if "JAT_INSTALL_WITH_SENTINEL" in block
        )
        prelude = install_block[: install_block.index("(\n  ulimit -c 0")]
        result = subprocess.run(
            ["/bin/sh"],
            input=prelude + ")\n",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_verified_installer_execution_survives_path_replacement(self) -> None:
        install_block = next(
            block
            for block in SHELL_BLOCKS
            if "JAT_INSTALL_WITH_SENTINEL" in block
        )
        capture_start = install_block.index('exec 5< "$JAT_INSTALL_COMMAND"')
        capture_end = install_block.index("unset JAT_INSTALL_PROGRAM")
        capture = install_block[capture_start:capture_end]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = root / "install-command.txt"
            result = root / "result"
            trusted = f"printf '%s' trusted > {result}".encode()
            malicious = f"printf '%s' malicious > {result}".encode()
            command.write_bytes(trusted)
            digest = hashlib.sha256(trusted).hexdigest()
            capture = capture.replace("5779", str(len(trusted))).replace(
                "485f80db51a14b1001ee58f5ed3174090d22fa6bf00d8e3324b8e94e87210be6",
                digest,
            )
            capture = capture.replace(
                'rm -f "$JAT_INSTALL_COMMAND"',
                'rm -f "$JAT_INSTALL_COMMAND"\n'
                f"printf '%s' {malicious.decode()!r} > \"$JAT_INSTALL_COMMAND\"",
                1,
            )
            executed = subprocess.run(
                ["/bin/sh"],
                input=(
                    "set -eu\n"
                    "PATH=/usr/bin:/bin\n"
                    f"JAT_INSTALL_COMMAND={command}\n"
                    + capture
                ),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(executed.returncode, 0, executed.stderr)
            self.assertEqual(result.read_text(encoding="utf-8"), "trusted")

    def test_every_shell_example_is_syntactically_valid(self) -> None:
        self.assertGreaterEqual(len(SHELL_BLOCKS), 9)
        for index, block in enumerate(SHELL_BLOCKS, start=1):
            with self.subTest(block=index):
                result = subprocess.run(
                    ["/bin/sh", "-n"],
                    input=block,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_guide_preserves_loopback_agentless_and_secret_boundaries(self) -> None:
        required = (
            "never installs a daemon on ordinary SSH",
            "literal loopback addresses",
            "SSH\nconnection",
            "Do not open port 37421",
            "Do not copy a bearer token",
            "Do not use raw\nHTTP requests",
            "Support bundles must not contain tokens",
        )
        for statement in required:
            with self.subTest(statement=statement):
                self.assertIn(statement, GUIDE)
        self.assertIn("net.JoinHostPort(\"127.0.0.1\"", CONFIG)
        self.assertIn("net.JoinHostPort(\"::1\"", CONFIG)

    def test_protection_modes_and_management_are_honest(self) -> None:
        required = (
            "Base mode",
            "Passphrase mode",
            "offline passphrase guessing",
            "supports the base-mode flow only",
            "Revocation blocks its future server access",
            "Revoking the last active device requires",
            "Rotate this device token",
            "Rotation\n   is self-only and exact-retry safe",
            "availability-gated operator contract",
            "not a claim that every\ncurrently published client",
            "Do not present it as a\ncompleted Task 2.6 walkthrough",
        )
        for statement in required:
            with self.subTest(statement=statement):
                self.assertIn(statement, GUIDE)

    def test_lifecycle_commands_match_the_shipping_cli(self) -> None:
        for operation in ("status", "rollback", "uninstall"):
            with self.subTest(operation=operation):
                self.assertIn(f"deploy {operation}", GUIDE)
                self.assertIn(f'case "{operation}":', CLI)
        for option in ("--home-dir", "--install-root", "--state-dir"):
            self.assertIn(option, GUIDE)
        self.assertIn("recovery_required", GUIDE)
        self.assertIn("deployment-journal.json", GUIDE)
        self.assertIn("foreground_required", GUIDE)
        self.assertIn("state.service_definition", GUIDE)
        self.assertIn(
            "credential-free deployment locator deliberately does not contain this path",
            GUIDE,
        )
        locator = re.search(
            r"type DeploymentLocator struct \{(?P<body>.*?)\n\}",
            LIFECYCLE,
            re.DOTALL,
        )
        self.assertIsNotNone(locator)
        self.assertNotIn("ServiceDefinition", locator.group("body"))

    def test_cold_backup_is_complete_stopped_sensitive_and_non_destructive(self) -> None:
        for name in (
            "config.json",
            "instance-secret",
            "server.db",
            "install-state.json",
        ):
            with self.subTest(name=name):
                self.assertIn(name, GUIDE)
                self.assertIn(f'filepath.Join(stateDir, "{name}")', CONFIG)
        required = (
            "fail-fast copy while the server is stopped",
            "mode-0700 state directory",
            "with mode 0600",
            "no `server.db-wal`,\n   `server.db-shm`, or `server.db-journal` file remains",
            "recoverable sibling rather than overwriting",
            "do not repair the copy by deleting a file",
            "manifest-driven admin backup\nand atomic-restore CLI",
            "test ! -e \"$JAT_BACKUP_NAME\"",
            "test ! -e \"$JAT_STATE_DIR\"",
            "SHA256SUMS",
            "regular non-symlink files",
            "does not bind the four files to one captured\ninstance",
            "a missing database can be initialized",
            "In foreground mode, restart the exact supervised argv",
            "partial, invalid attempt; never reuse it as a backup",
            '"$JAT_BACKUP_DIR"/.[!.]*',
            'config != 1 || secret != 1 || database != 1 || state != 1',
            'for name in .enrollment.sock server.db-wal server.db-shm server.db-journal',
            "JAT_BACKUP_PARENT_ID=$(stat -f '%u:%Lp' . 2>/dev/null)",
            'JAT_BACKUP_DIR="$JAT_BACKUP_PARENT/$JAT_BACKUP_NAME"',
            'cd "$JAT_BACKUP_NAME"',
            'test "$(pwd -P)" = "$JAT_BACKUP_DIR"',
        )
        for statement in required:
            with self.subTest(statement=statement):
                self.assertIn(statement, GUIDE)
        self.assertNotIn("mixed restore must remain offline", GUIDE)

    def test_cold_backup_and_restore_examples_fail_closed_in_a_temp_fixture(self) -> None:
        backup_block = next(
            block
            for block in SHELL_BLOCKS
            if 'mkdir -m 700 "$JAT_BACKUP_NAME"' in block
            and 'cp -p \\\n' in block
        )
        restore_block = next(
            block
            for block in SHELL_BLOCKS
            if 'awk \'\n' in block
            and 'sha256sum -c "$JAT_BACKUP_DIR/SHA256SUMS"' in block
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir(mode=0o700)
            payloads = {
                "config.json": b'{"version":1}\n',
                "instance-secret": bytes(range(32)),
                "server.db": b"sqlite-fixture",
                "install-state.json": b'{"status":"active"}\n',
            }
            for name, payload in payloads.items():
                path = source / name
                path.write_bytes(payload)
                path.chmod(0o600)

            backup = root / "backup"
            environment = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "LC_ALL": "C",
                "JAT_STATE_DIR": str(source),
                "JAT_BACKUP_DIR": str(backup),
            }
            captured = subprocess.run(
                ["/bin/sh"],
                input=backup_block,
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            self.assertEqual(captured.returncode, 0, captured.stderr)
            self.assertEqual(
                {entry.name for entry in backup.iterdir()},
                set(payloads) | {"SHA256SUMS"},
            )
            original = {entry.name: entry.read_bytes() for entry in backup.iterdir()}

            repeated = subprocess.run(
                ["/bin/sh"],
                input=backup_block,
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(
                {entry.name: entry.read_bytes() for entry in backup.iterdir()},
                original,
            )

            unsafe_parent = root / "unsafe-parent"
            unsafe_parent.mkdir(mode=0o777)
            unsafe_parent.chmod(0o777)
            unsafe_backup = unsafe_parent / "backup"
            unsafe_result = subprocess.run(
                ["/bin/sh"],
                input=backup_block,
                text=True,
                capture_output=True,
                env=environment | {"JAT_BACKUP_DIR": str(unsafe_backup)},
                check=False,
            )
            self.assertNotEqual(unsafe_result.returncode, 0)
            self.assertFalse(unsafe_backup.exists())

            for mode in (0o2750, 0o1700):
                with self.subTest(secure_special_parent_mode=oct(mode)):
                    special_parent = root / f"special-parent-{mode:o}"
                    special_parent.mkdir(mode=0o700)
                    special_parent.chmod(mode)
                    special_backup = special_parent / "backup"
                    special_result = subprocess.run(
                        ["/bin/sh"],
                        input=backup_block,
                        text=True,
                        capture_output=True,
                        env=environment
                        | {"JAT_BACKUP_DIR": str(special_backup)},
                        check=False,
                    )
                    self.assertEqual(
                        special_result.returncode,
                        0,
                        special_result.stderr,
                    )
                    self.assertEqual(
                        {entry.name for entry in special_backup.iterdir()},
                        set(payloads) | {"SHA256SUMS"},
                    )

            restored = root / "restored"
            restore_environment = environment | {"JAT_STATE_DIR": str(restored)}
            result = subprocess.run(
                ["/bin/sh"],
                input=restore_block,
                text=True,
                capture_output=True,
                env=restore_environment,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                {entry.name: entry.read_bytes() for entry in restored.iterdir()},
                payloads,
            )

            extra = backup / ".unexpected"
            extra.write_bytes(b"reject")
            extra_destination = root / "extra-destination"
            extra_result = subprocess.run(
                ["/bin/sh"],
                input=restore_block,
                text=True,
                capture_output=True,
                env=environment | {"JAT_STATE_DIR": str(extra_destination)},
                check=False,
            )
            self.assertNotEqual(extra_result.returncode, 0)
            self.assertFalse(extra_destination.exists())
            extra.unlink()

            manifest = backup / "SHA256SUMS"
            manifest.write_bytes(original["SHA256SUMS"] + original["SHA256SUMS"].splitlines(keepends=True)[0])
            duplicate_destination = root / "duplicate-destination"
            duplicate_result = subprocess.run(
                ["/bin/sh"],
                input=restore_block,
                text=True,
                capture_output=True,
                env=environment | {"JAT_STATE_DIR": str(duplicate_destination)},
                check=False,
            )
            self.assertNotEqual(duplicate_result.returncode, 0)
            self.assertFalse(duplicate_destination.exists())
            manifest.write_bytes(original["SHA256SUMS"])

            (backup / "server.db").write_bytes(b"tampered")
            mismatch_destination = root / "mismatch-destination"
            mismatch_result = subprocess.run(
                ["/bin/sh"],
                input=restore_block,
                text=True,
                capture_output=True,
                env=environment | {"JAT_STATE_DIR": str(mismatch_destination)},
                check=False,
            )
            self.assertNotEqual(mismatch_result.returncode, 0)
            self.assertFalse(mismatch_destination.exists())

            incomplete_source = root / "incomplete-source"
            incomplete_source.mkdir(mode=0o700)
            for name in ("config.json", "instance-secret", "install-state.json"):
                (incomplete_source / name).write_bytes(payloads[name])
            incomplete_backup = root / "incomplete-backup"
            incomplete_result = subprocess.run(
                ["/bin/sh"],
                input=backup_block,
                text=True,
                capture_output=True,
                env=environment
                | {
                    "JAT_STATE_DIR": str(incomplete_source),
                    "JAT_BACKUP_DIR": str(incomplete_backup),
                },
                check=False,
            )
            self.assertNotEqual(incomplete_result.returncode, 0)
            self.assertTrue(incomplete_backup.is_dir())
            self.assertEqual(list(incomplete_backup.iterdir()), [])

            wal = source / "server.db-wal"
            wal.write_bytes(b"uncheckpointed")
            wal_backup = root / "wal-backup"
            wal_result = subprocess.run(
                ["/bin/sh"],
                input=backup_block,
                text=True,
                capture_output=True,
                env=environment | {"JAT_BACKUP_DIR": str(wal_backup)},
                check=False,
            )
            self.assertNotEqual(wal_result.returncode, 0)
            self.assertTrue(wal_backup.is_dir())
            self.assertEqual(list(wal_backup.iterdir()), [])
            wal.unlink()

            journal = source / "server.db-journal"
            journal.write_bytes(b"pending rollback")
            journal_backup = root / "journal-backup"
            journal_result = subprocess.run(
                ["/bin/sh"],
                input=backup_block,
                text=True,
                capture_output=True,
                env=environment | {"JAT_BACKUP_DIR": str(journal_backup)},
                check=False,
            )
            self.assertNotEqual(journal_result.returncode, 0)
            self.assertTrue(journal_backup.is_dir())
            self.assertEqual(list(journal_backup.iterdir()), [])

    def test_human_and_native_acceptance_remain_nonclaims(self) -> None:
        self.assertIn("human under-15-minute\nwalkthrough", GUIDE)
        self.assertIn("full native OS/architecture acceptance matrix", GUIDE)
        self.assertIn("does not claim either run has occurred", GUIDE)


if __name__ == "__main__":
    unittest.main()
