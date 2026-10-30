import base64
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
NGINX = shutil.which(os.environ.get("TEST_NGINX_BINARY", "nginx"))
VERSIONS = (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    print("PASS:", name, flush=True)


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def make_key(start, end, expiry, lifetime=300, name=None):
    raw = os.urandom(80)
    if name is not None:
        raw = name + raw[16:]
    return {
        "key": base64.b64encode(raw).decode(),
        "encrypt_from": start,
        "encrypt_until": end,
        "decrypt_until": expiry,
        "lifetime": lifetime,
    }


def context(version):
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    client.minimum_version = version
    client.maximum_version = version
    return client


def connect(client, port, session=None, stream=False):
    with socket.create_connection(("127.0.0.1", port), timeout=12) as raw:
        with client.wrap_socket(raw, server_hostname="ticket.test", session=session) as connection:
            if not stream:
                connection.sendall(b"GET / HTTP/1.0\r\nHost: ticket.test\r\n\r\n")
            response = b""
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                response += chunk
            if stream:
                assert response == b"ok", response
                worker_pid = None
            else:
                assert b"200 OK" in response, response
                worker_pid = int(response.split(b"\r\n\r\n", 1)[1].split(b":", 1)[0])
            return connection.session, connection.session_reused, worker_pid


def wait_until(deadline):
    while time.time() < deadline:
        time.sleep(0.05)


class Node:
    def __init__(self, suite, name, managed=True, static_key=None, cleanup=True,
                 shared_cache=True, tickets_on=True, early_data=False,
                 hello_delay=0, certificate_delay=0):
        self.root = suite.root / name
        self.root.mkdir()
        self.port, self.control, self.admin, self.stream = [unused_port() for _ in range(4)]
        self.sequence = 0
        self.fixture = self.root / "keys.json"
        self.fixture.write_text(json.dumps({"sequence": 0, "keys": []}))
        self.process = None
        self.output = None
        suite.nodes.append(self)
        (self.root / "admin.key").write_bytes(bytes(range(80)))
        runtime = ""
        hooks = ""
        if managed:
            runtime = f'''
                init_worker_by_lua_block {{
                    require("ssl_session_ticket_fixture").start(
                        "{self.fixture}", {str(cleanup).lower()})
                }}
            '''
            hooks = f'''
                ssl_client_hello_by_lua_block {{
                    local ok, err = require("resty.apisix.ssl_session_ticket").on_client_hello()
                    if not ok then
                        ngx.log(ngx.ERR, err)
                        return ngx.exit(ngx.ERROR)
                    end
                    ngx.sleep({hello_delay})
                }}
            '''
            if certificate_delay:
                hooks += f"ssl_certificate_by_lua_block {{ ngx.sleep({certificate_delay}) }}"
        key_config = ""
        if static_key is not None:
            (self.root / "ticket.key").write_bytes(base64.b64decode(static_key["key"]))
            key_config = f"ssl_session_ticket_key {self.root}/ticket.key;"
        cache = "shared:SSL:1m" if shared_cache else "none"
        config = f'''
            worker_processes 2;
            daemon off;
            pid {self.root}/nginx.pid;
            error_log {self.root}/error.log notice;
            events {{ worker_connections 128; }}
            stream {{
                server {{
                    listen 127.0.0.1:{self.stream} ssl;
                    ssl_certificate {suite.root}/cert.pem;
                    ssl_certificate_key {suite.root}/key.pem;
                    ssl_protocols TLSv1.2 TLSv1.3;
                    ssl_session_cache shared:STREAM:1m;
                    ssl_session_timeout 10m;
                    ssl_session_tickets on;
                    return "ok";
                }}
            }}
            http {{
                access_log off;
                lua_package_path "{ROOT}/lib/?.lua;{ROOT}/t/lib/?.lua;;";
                ssl_protocols TLSv1.2 TLSv1.3;
                ssl_certificate {suite.root}/cert.pem;
                ssl_certificate_key {suite.root}/key.pem;
                {runtime}
                server {{
                    listen 127.0.0.1:{self.port} ssl;
                    server_name ticket.test;
                    ssl_session_cache {cache};
                    ssl_session_timeout 10m;
                    ssl_session_tickets {"on" if tickets_on else "off"};
                    ssl_early_data {"on" if early_data else "off"};
                    {key_config}
                    {hooks}
                    location / {{ return 200 "$pid:$ssl_session_reused"; }}
                }}
                server {{
                    listen 127.0.0.1:{self.admin} ssl;
                    ssl_session_cache shared:ADMIN:1m;
                    ssl_session_tickets on;
                    ssl_session_ticket_key {self.root}/admin.key;
                    location / {{ return 200 "$pid:$ssl_session_reused"; }}
                }}
                server {{
                    listen 127.0.0.1:{self.control};
                    location / {{
                        content_by_lua_block {{
                            ngx.say(require("cjson").encode(
                                require("ssl_session_ticket_fixture").status()))
                        }}
                    }}
                }}
            }}
        '''
        configuration = self.root / "nginx.conf"
        configuration.write_text(config)
        command = [NGINX, "-p", str(self.root) + "/", "-c", str(configuration)]
        tested = subprocess.run(command + ["-t"], capture_output=True, text=True)
        if tested.returncode:
            raise RuntimeError(tested.stderr)
        self.output = (self.root / "stderr.log").open("w")
        self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=self.output)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                self.status()
                return
            except (OSError, ValueError):
                time.sleep(0.05)
        raise RuntimeError("NGINX failed to start: " + name)

    def status(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.control}/", timeout=2) as response:
            return json.load(response)

    def apply(self, keys, expected_error=None):
        self.sequence += 1
        temporary = self.fixture.with_suffix(".new")
        temporary.write_text(json.dumps({"sequence": self.sequence, "keys": keys}))
        temporary.replace(self.fixture)
        workers = set()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(workers) < 2:
            status = self.status()
            if status.get("sequence") == self.sequence:
                if expected_error is None:
                    assert not status.get("error"), status.get("error")
                else:
                    assert expected_error in status.get("error", ""), status.get("error")
                workers.add(status["worker_pid"])
            time.sleep(0.01)
        assert len(workers) == 2, "both workers must apply the key set"


class Suite:
    def __init__(self, root):
        self.root = root
        self.nodes = []

    def close(self, failed):
        failures = []
        for node in self.nodes:
            if node.process is not None and node.process.poll() is None:
                node.process.send_signal(signal.SIGQUIT)
        for node in self.nodes:
            if node.process is not None:
                try:
                    node.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    node.process.kill()
                    node.process.wait(timeout=5)
                if node.process.returncode:
                    failures.append(f"{node.root.name}: exit {node.process.returncode}")
            if node.output is not None:
                node.output.close()
            if failed or failures:
                for filename in ("error.log", "stderr.log"):
                    path = node.root / filename
                    if path.exists():
                        print(f"--- {node.root.name}/{filename} ---\n{path.read_text()}", flush=True)
        if failures and not failed:
            raise AssertionError("unclean NGINX shutdown: " + ", ".join(failures))

    def run(self):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(self.root / "key.pem"), "-out", str(self.root / "cert.pem"),
                        "-days", "1", "-subj", "/CN=ticket.test"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        first = Node(self, "node-a")
        if not first.status()["supported"]:
            print("SKIP: native dynamic session ticket patch is not available", flush=True)
            return
        second = Node(self, "node-b", cleanup=False)
        clients = {version: context(version) for version in VERSIONS}
        for version, client in clients.items():
            session, _, original_pid = connect(client, first.port)
            cross_worker = False
            for _ in range(50):
                _, reused, worker_pid = connect(client, first.port, session)
                if worker_pid != original_pid and reused:
                    cross_worker = True
                    break
            _, cross_node, _ = connect(client, second.port, session)
            check(f"{version.name}: empty keys use the node-local shared cache across workers",
                  cross_worker and not cross_node)

        now = int(time.time())
        current = make_key(now - 10, now + 3600, now + 4000)
        future = make_key(now + 1800, now + 5400, now + 5800)
        first.apply([current, future])
        second.apply([current, future])
        native = Node(self, "native", managed=False, static_key=current)
        preloaded = Node(self, "preloaded", managed=False, static_key=future)
        saved = {}
        for version, client in clients.items():
            session, _, _ = connect(client, first.port)
            saved[version] = session
            _, reused, _ = connect(client, second.port, session)
            check(f"{version.name}: dynamic keys resume across nodes", session.has_ticket and reused)
            check(f"{version.name}: signing key lifetime is applied", session.ticket_lifetime_hint == 300)
            _, forward, _ = connect(client, native.port, session)
            native_session, _, _ = connect(client, native.port)
            _, reverse, _ = connect(client, first.port, native_session)
            check(f"{version.name}: native 80-byte key files interoperate in both directions", forward and reverse)
            future_session, _, _ = connect(client, preloaded.port)
            renewed, reused, _ = connect(client, second.port, future_session)
            _, renewed_current, _ = connect(client, native.port, renewed)
            check(f"{version.name}: future keys decrypt and renew with the current signer",
                  reused and renewed_current)
            admin_session, _, _ = connect(client, first.admin)
            _, admin_reused, _ = connect(client, second.admin, admin_session)
            check(f"{version.name}: unbound Admin HTTPS retains native key-file behavior", admin_reused)
            stream_session, _, _ = connect(client, first.stream, stream=True)
            _, same, _ = connect(client, first.stream, stream_session, stream=True)
            _, different, _ = connect(client, second.stream, stream_session, stream=True)
            check(f"{version.name}: stream retains native node-local tickets", same and not different)

        second.apply([current, current], expected_error="duplicate session ticket key name")
        for version, client in clients.items():
            _, reused, _ = connect(client, second.port, saved[version])
            check(f"{version.name}: rejected duplicate names preserve the previous key snapshot", reused)

        replacement = make_key(now - 1, now + 3600, now + 4000, lifetime=600)
        second.apply([replacement])
        for version, client in clients.items():
            session, reused, _ = connect(client, second.port, saved[version])
            check(f"{version.name}: removal revokes old keys and updates lifetime",
                  not reused and session.ticket_lifetime_hint == 600)

        boundary = int(time.time()) + 3
        old = make_key(boundary - 30, boundary, boundary + 4)
        next_key = make_key(boundary, boundary + 30, boundary + 60)
        first.apply([old, next_key])
        second.apply([old, next_key])
        rotating = {version: connect(client, first.port)[0] for version, client in clients.items()}
        wait_until(boundary + 0.1)
        for version, client in clients.items():
            renewed, reused, _ = connect(client, second.port, rotating[version])
            first.apply([next_key])
            _, current_only, _ = connect(client, first.port, renewed)
            check(f"{version.name}: time-based rotation accepts old keys and renews without an update",
                  reused and current_only)
        wait_until(boundary + 4.1)
        for version, client in clients.items():
            _, reused, _ = connect(client, second.port, rotating[version])
            check(f"{version.name}: decrypt expiry is enforced without cleanup timers", not reused)

        boundary = int(time.time()) + 2
        short = make_key(boundary - 30, boundary, boundary + 30)
        second.apply([short])
        signed = {version: connect(client, second.port)[0] for version, client in clients.items()}
        wait_until(boundary + 0.1)
        for version, client in clients.items():
            _, reused, _ = connect(client, second.port, signed[version])
            local_session, _, _ = connect(client, second.port)
            _, local_reused, _ = connect(client, second.port, local_session)
            check(f"{version.name}: a signing gap rejects tickets and uses local cache", not reused and local_reused)
        first.apply([replacement])
        second.apply([replacement])
        for version, client in clients.items():
            session, _, _ = connect(client, second.port)
            _, reused, _ = connect(client, first.port, session)
            check(f"{version.name}: valid keys recover without reload", reused)

        connections = []
        try:
            for version, client in clients.items():
                connection = client.wrap_socket(socket.create_connection(("127.0.0.1", first.port)),
                                                server_hostname="ticket.test")
                connection.settimeout(3)
                connection.sendall(b"GET / HTTP/1.1\r\nHost: ticket.test\r\n\r\n")
                response = b""
                while b"\r\n\r\n" not in response:
                    response += connection.recv(65536)
                headers, body = response.split(b"\r\n\r\n", 1)
                length = int(next(line.split(b":", 1)[1] for line in headers.split(b"\r\n")
                                  if line.lower().startswith(b"content-length:")))
                while len(body) < length:
                    body += connection.recv(65536)
                connections.append((version, connection))
            first.apply([])
            for version, connection in connections:
                connection.sendall(b"GET / HTTP/1.1\r\nHost: ticket.test\r\nConnection: close\r\n\r\n")
                check(f"{version.name}: established HTTPS survives key revocation",
                      b"200 OK" in connection.recv(65536))
        finally:
            for _, connection in connections:
                connection.close()

        now = int(time.time())
        overlap = [make_key(now - 1, now + 60, now + 300, name=bytes([value]) * 16)
                   for value in (1, 2)]
        older = make_key(now - 2, now + 60, now + 300, name=bytes([255]) * 16)
        first.apply([overlap[0], older, overlap[1]])
        selected = Node(self, "selected", managed=False, static_key=overlap[1])
        automatic = Node(self, "automatic", managed=False)
        for version, client in clients.items():
            session, _, _ = connect(client, first.port)
            _, reused, _ = connect(client, selected.port, session)
            check(f"{version.name}: newest signing start and greatest key name select deterministically", reused)
            session, _, _ = connect(client, automatic.port)
            _, reused, _ = connect(client, automatic.port, session)
            check(f"{version.name}: unbound HTTP keeps native automatic rotation", reused)

        for name, options in (
            ("no-shared-cache", {"shared_cache": False}),
            ("tickets-off", {"tickets_on": False}),
            ("early-data", {"early_data": True}),
            ("explicit-key-file", {"static_key": replacement}),
        ):
            invalid = Node(self, name, **options)
            rejected = False
            try:
                connect(context(ssl.TLSVersion.TLSv1_3), invalid.port)
            except (ssl.SSLError, ConnectionError):
                rejected = True
            check(f"invalid binding {name} fails before issuing tickets", rejected)

        slow_decrypt = Node(self, "slow-decrypt", cleanup=False, hello_delay=6)
        slow_sign = Node(self, "slow-sign", cleanup=False, certificate_delay=3)
        for version, client in clients.items():
            now = int(time.time())
            expiring = make_key(now - 10, now + 4, now + 5)
            next_valid = make_key(now + 4, now + 60, now + 120)
            second.apply([expiring, next_valid])
            slow_decrypt.apply([expiring, next_valid])
            session, _, _ = connect(client, second.port)
            started = time.monotonic()
            _, reused, _ = connect(client, slow_decrypt.port, session)
            check(f"{version.name}: native decrypt callback rechecks time after a slow ClientHello",
                  not reused and time.monotonic() - started >= 5.8)
            now = int(time.time())
            slow_sign.apply([make_key(now - 10, now + 2, now + 120)])
            session, _, _ = connect(client, slow_sign.port)
            check(f"{version.name}: native encrypt callback rejects an expired signing window",
                  not session.has_ticket)

        check("all masters remain running without reload",
              all(node.process.poll() is None for node in self.nodes))


def main():
    if NGINX is None:
        raise RuntimeError("set TEST_NGINX_BINARY or put nginx in PATH")
    with tempfile.TemporaryDirectory(prefix="apisix-ticket-") as directory:
        suite = Suite(Path(directory))
        failed = True
        try:
            suite.run()
            failed = False
        finally:
            suite.close(failed)


if __name__ == "__main__":
    main()
