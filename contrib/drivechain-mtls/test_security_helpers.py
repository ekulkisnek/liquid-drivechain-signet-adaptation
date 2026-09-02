#!/usr/bin/env python3
"""Offline operational regressions; no nodes, funds, or existing services are used."""

import hashlib
import itertools
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / "contrib" / "drivechain-mtls"
sys.path.insert(0, str(ROOT / "contrib" / "assets_tutorial"))
from test_framework.daemon import Daemon  # noqa: E402


def run(*args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=30, **kwargs)


@unittest.skipUnless(shutil.which("openssl"), "openssl required")
class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="elements-tls-test-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.credentials = Path(cls.directory.name) / "credentials"
        result = run("bash", str(HELPERS / "generate-certs.sh"), str(cls.credentials))
        if result.returncode:
            raise RuntimeError(result.stderr)

    def test_certificate_permissions_purposes_and_expiry(self):
        ca = self.credentials / "ca.pem"
        self.assertEqual(self.credentials.stat().st_mode & 0o777, 0o700)
        for name in ("ca-key.pem", "server-key.pem", "elements-client-key.pem"):
            self.assertEqual((self.credentials / name).stat().st_mode & 0o777, 0o600)
        for name, purpose, days in (("ca.pem", None, 365),
                                    ("server.pem", "sslserver", 90),
                                    ("elements-client.pem", "sslclient", 90)):
            cert = self.credentials / name
            self.assertEqual(cert.stat().st_mode & 0o777, 0o644)
            if purpose:
                result = run("openssl", "verify", "-purpose", purpose,
                             "-CAfile", str(ca), str(cert))
                self.assertEqual(result.returncode, 0, result.stderr)
            dates = run("openssl", "x509", "-in", str(cert), "-noout", "-dates")
            self.assertEqual(dates.returncode, 0, dates.stderr)
            values = dict(line.split("=", 1) for line in dates.stdout.splitlines())
            duration = (ssl.cert_time_to_seconds(values["notAfter"]) -
                        ssl.cert_time_to_seconds(values["notBefore"]))
            self.assertEqual(duration, days * 86400)
        server = run("openssl", "x509", "-in", str(self.credentials / "server.pem"),
                     "-noout", "-text")
        self.assertIn("DNS:enforcer.local", server.stdout)
        self.assertIn("IP Address:127.0.0.1", server.stdout)
        self.assertIn("IP Address:0:0:0:0:0:0:0:1", server.stdout)

    def test_refuses_overwrite_and_dangling_symlink(self):
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in self.credentials.iterdir() if p.is_file()}
        result = run("bash", str(HELPERS / "generate-certs.sh"), str(self.credentials))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to overwrite", result.stderr)
        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in self.credentials.iterdir() if p.is_file()}
        self.assertEqual(before, after)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.pem"
            path.symlink_to("missing.pem")
            result = run("bash", str(HELPERS / "generate-certs.sh"), directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing to overwrite", result.stderr)
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ["server.pem"])

    def test_mutual_tls_handshake(self):
        # Actual TLS handshakes exercise both directions of authentication.
        for client_identity, hostname, trusted in (
                ("elements-client", "enforcer.local", True),
                (None, "enforcer.local", True),
                ("server", "enforcer.local", True),
                ("elements-client", "wrong.local", True),
                ("elements-client", "enforcer.local", False)):
            with self.subTest(client=client_identity, hostname=hostname, trusted=trusted):
                server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server.load_cert_chain(str(self.credentials / "server.pem"),
                                       str(self.credentials / "server-key.pem"))
                server.load_verify_locations(str(self.credentials / "ca.pem"))
                server.verify_mode = ssl.CERT_REQUIRED
                client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if trusted:
                    client.load_verify_locations(str(self.credentials / "ca.pem"))
                if client_identity:
                    client.load_cert_chain(str(self.credentials / (client_identity + ".pem")),
                                           str(self.credentials / (client_identity + "-key.pem")))
                outcomes = []
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(1)
                    listener.settimeout(5)

                    def serve():
                        try:
                            connection, _ = listener.accept()
                            with connection:
                                connection.settimeout(5)
                                with server.wrap_socket(connection, server_side=True) as tls:
                                    outcomes.append(tls.recv(1) == b"x")
                                    tls.sendall(b"y")
                        except (ssl.SSLError, OSError):
                            outcomes.append(False)

                    worker = threading.Thread(target=serve)
                    worker.start()
                    success = False
                    try:
                        with socket.create_connection(listener.getsockname(), timeout=5) as connection:
                            with client.wrap_socket(connection, server_hostname=hostname) as tls:
                                tls.sendall(b"x")
                                success = tls.recv(1) == b"y"
                    except (ssl.SSLError, OSError):
                        pass
                    finally:
                        worker.join(10)
                    self.assertFalse(worker.is_alive())
                    expected = client_identity == "elements-client" and hostname == "enforcer.local" and trusted
                    self.assertEqual(success, expected)
                    self.assertEqual(outcomes, [expected])

    @unittest.skipUnless(shutil.which("stunnel"), "stunnel required")
    def test_proxy_forwards_authenticated_client(self):
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.load_verify_locations(str(self.credentials / "ca.pem"))
        client.load_cert_chain(str(self.credentials / "elements-client.pem"),
                               str(self.credentials / "elements-client-key.pem"))
        with socket.socket() as upstream, socket.socket() as reservation:
            upstream.bind(("127.0.0.1", 0))
            upstream.listen(1)
            upstream.settimeout(10)
            reservation.bind(("127.0.0.1", 0))
            endpoint = reservation.getsockname()
            reservation.close()
            outcomes = []

            def serve():
                try:
                    connection, _ = upstream.accept()
                    with connection:
                        connection.settimeout(5)
                        outcomes.append(connection.recv(1) == b"x")
                        connection.sendall(b"y")
                except OSError:
                    outcomes.append(False)

            with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as log:
                environment = dict(os.environ, TMPDIR=directory)
                process = subprocess.Popen(
                    ["bash", str(HELPERS / "run-stunnel-proxy.sh"), str(self.credentials),
                     f"127.0.0.1:{endpoint[1]}", f"127.0.0.1:{upstream.getsockname()[1]}"],
                    env=environment, stdout=log, stderr=log)
                worker = threading.Thread(target=serve)
                worker.start()
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            connection = socket.create_connection(endpoint, timeout=2)
                            break
                        except ConnectionRefusedError:
                            if process.poll() is not None or time.monotonic() >= deadline:
                                log.seek(0)
                                self.fail(log.read().decode(errors="replace"))
                            time.sleep(0.05)
                    with connection:
                        with client.wrap_socket(connection, server_hostname="enforcer.local") as tls:
                            tls.sendall(b"x")
                            self.assertEqual(tls.recv(1), b"y")
                    self.assertEqual(outcomes, [True])
                finally:
                    process.terminate()
                    try:
                        process.wait(5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(5)
                    worker.join(12)
                    self.assertFalse(worker.is_alive())

    @unittest.skipUnless(shutil.which("stunnel"), "stunnel required")
    def test_proxy_rejects_non_numeric_or_non_loopback_endpoints(self):
        for endpoint in ("127.attacker.example:50051", "localhost:50051", "192.168.1.1:50051",
                         "0.0.0.0:55051", "127.0.0.256:1", "127.01.0.1:1", "127.0.0.1:0",
                         "127.0.0.1:65536", "[::]:55051", "127.0.0.1:1\nclient=yes"):
            for position in (0, 1):
                with self.subTest(endpoint=endpoint, position=position):
                    endpoints = ["127.0.0.1:55051", "127.0.0.1:50051"]
                    endpoints[position] = endpoint
                    result = run("bash", str(HELPERS / "run-stunnel-proxy.sh"),
                                 str(self.credentials), *endpoints)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("refusing non-loopback or invalid", result.stderr)


class RepositoryTests(unittest.TestCase):
    def test_tutorial_credentials_are_private_random_and_shared_with_parent(self):
        base = ROOT / "contrib" / "assets_tutorial"
        parent = Daemon("parent", "bitcoin", "unused", str(base / "bitcoin.conf"))
        child = Daemon("child", "elements", "unused", str(base / "elements1.conf"))
        other = Daemon("other", "elements", "unused", str(base / "elements2.conf"))
        self.assertRegex(parent.config["rpcpassword"], r"^[0-9a-f]{64}$")
        self.assertEqual(parent.config["rpcpassword"], child.config["mainchainrpcpassword"])
        self.assertNotEqual(parent.config["rpcpassword"], child.config["rpcpassword"])
        self.assertNotEqual(child.config["rpcpassword"], other.config["rpcpassword"])
        with tempfile.TemporaryDirectory() as directory:
            child.datadir_path = directory
            try:
                child.write_config()
                configuration = Path(directory) / "elements.conf"
                self.assertEqual(configuration.stat().st_mode & 0o777, 0o600)
                contents = configuration.read_text()
                self.assertIn("rpcpassword=" + child.config["rpcpassword"], contents)
                self.assertIn("mainchainrpcpassword=" + parent.config["rpcpassword"], contents)
                self.assertNotIn("password1", contents)
                with self.assertRaises(FileExistsError):
                    child.write_config()
                self.assertEqual(configuration.read_text(), contents)
            finally:
                child.datadir_path = None

    @unittest.skipUnless(shutil.which("c++"), "C++ preprocessor required")
    def test_identity_headers_cannot_be_mixed(self):
        headers = ("elements_drivechain_identity.h", "elements_drivechain_identity.alphanet.h",
                   "elements_drivechain_identity.alphanet.v2.h")
        for first, second in itertools.product(headers, repeat=2):
            with self.subTest(first=first, second=second):
                result = run("c++", "-std=c++17", "-E", "-x", "c++", "-I", str(ROOT / "src"), "-",
                             input=f'#include <{first}>\n#include <{second}>\n')
                if first == second:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Multiple frozen Elements network identities", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
