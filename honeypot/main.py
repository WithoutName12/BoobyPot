#!/bin/env python3

import os
import socket
import threading
import sys
import random
import json
import datetime
import time
import argparse
import subprocess
import configparser

LOG_PATH = "/var/logs/"
FTP_ROOT = "/var/files_ftp/"


class Honeypot:
    def __init__(
        self,
        host,
    ):
        self.host = host
        default_banners = {
            "ftp": "220 (vsFTPd 3.0.3) Ubuntu Linux ready.",
        }
        self.config = configparser.ConfigParser()
        read_files = self.config.read("config.ini")
        if not read_files or not self.config.has_option("ftp", "banner"):
            self.banners = {21: default_banners["ftp"]}
        else:
            self.banners = {21: self.config.get("ftp", "banner")}
        if (
            not read_files
            or not self.config.has_option("ftp", "user")
            or not self.config.has_option("ftp", "password")
        ):
            self.config = configparser.ConfigParser()
            self.config["ftp"] = {}
            self.config["ftp"]["user"] = "admin"
            self.config["ftp"]["password"] = "admin"
            print(
                "[*] No ftp user and password provided, using Defaults (admin, admin)"
            )

    def listen_connection(self, port, backlog=5):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.host, port))
            s.listen(backlog)
            print(f"[+] Listening on {self.host}:{port}")
            while True:
                try:
                    conn, addr = s.accept()
                    self.server_ip, self.server_port = conn.getsockname()
                    print(f"[+] Connection from {addr}")
                    self.handle_client(conn, addr)
                    conn.close()
                except socket.error as e:
                    print("[-] Client handler error:", e)
        except socket.error as e:
            print(f"[-] Could not start server: {e}")
        finally:
            s.close()
            print("[+] Socket closed")

    def connect_active(self, dst_ip, dst_port):
        active_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        active_socket.connect((dst_ip, dst_port))
        return active_socket

    def handle_client(self, conn, addr):
        """Handle client, send banners, and default message"""
        with conn:
            self.filename = f"{LOG_PATH}{str(self.server_port)}/{addr[0]}:{addr[1]}-{datetime.datetime.now().isoformat()}.json"
            if self.server_port != 80:
                conn.sendall(self.banners[self.server_port].encode() + "\r\n".encode())
            default = b"Command is not recognized.\r\n"

            if self.server_port == 21:
                RESPONSES = {
                    "USER": lambda arg: f"331 Password required for {arg}\r\n",
                    "PASS": lambda arg: f"230 User: {arg} logged in, proceed.\r\n",
                    "SYST": lambda arg: "215 UNIX Type: L8\r\n",
                    "PWD": lambda arg: '257 "/" is the current directory\r\n',
                    "LIST": lambda arg: (
                        # "150 Opening data connection for directory list\r\n"
                        "drwxr-xr-x  2 user group 4096 Jan 01 00:00 pub\r\n"
                        "-rw-r--r--  1 user group 1024 Jan 01 00:00 readme.txt\r\n"
                    ),
                    # Ignore  LPRT, at least now
                    "LPRT": b"",
                    "QUIT": lambda arg: "221 Goodbye.\r\n",
                }
                default_handler = lambda arg: "502 Command not implemented.\r\n"
                host = conn.getsockname()[0]
                while True:
                    data = conn.recv(1024).decode(errors="ignore")
                    if not data:
                        break
                    self.write_logs(addr, data)
                    parts = data.strip().split(maxsplit=2)
                    cmd = parts[0].upper()
                    arg = parts[1] if len(parts) > 1 else None

                    arg2 = (
                        parts[2]
                        if len(parts) > 2 and parts[2]
                        else (arg.split("/")[-1] if arg else "")
                    )
                    print(cmd)
                    print(arg)
                    response = RESPONSES.get(cmd, default_handler)(arg or "")

                    if cmd == "TYPE":
                        if arg in ("A", "I", "E"):
                            self.transfer_type = arg
                        else:
                            response = (
                                "504 Command not implemented for that parameter.\r\n"
                            )

                    if cmd == "USER" and not arg:
                        response = "501 Syntax error in parameters or arguments.\r\n"
                        logged_in = False
                    elif cmd == "USER" and arg:
                        user = arg
                        response = RESPONSES.get(cmd, default_handler)(arg or "")
                        logged_in = False

                    if cmd == "PASS" and not arg:
                        response = "501 Syntax error in parameters or arguments.\r\n"
                        logged_in = False
                    elif cmd == "PASS" and arg:
                        if (
                            user == self.config["ftp"]["user"]
                            and arg == self.config["ftp"]["password"]
                        ):
                            response = RESPONSES.get(cmd, default_handler)(user)
                            logged_in = True
                        else:
                            response = "530 Login incorrect.\r\n"
                            logged_in = False

                    # Opem active connection
                    if cmd == "PORT":
                        arg = arg.strip().split(",")
                        active_dst_ip = ".".join(arg[0:4])
                        active_dst_port = int(arg[4]) * 256 + int(arg[5])
                        conn.sendall(b"200 PORT command successful\r\n")
                        continue
                    # Open Passive connection
                    if cmd == "PASV":
                        not_found = True
                        pasv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        while not_found:
                            try:
                                pasv_port = random.randint(20000, 30000)
                                pasv_sock.bind((host, pasv_port))
                                not_found = False
                            except (OSError, socket.error) as e:
                                print("[-]", e)
                                continue
                        pasv_sock.listen()
                        host_parts = host.split(".")
                        # According to RFC 959, port should be represanted with two 8 bit parts. https://www.rfc-editor.org/rfc/rfc959
                        p1 = (
                            (pasv_port >> 8) & 0xFF
                        )  # Shift to right, do bitewise AND with FF, so fillers (0-s) get removed
                        p2 = pasv_port % 256
                        print(f"[+] Listening on {self.host}:{pasv_port}")
                        # Format is 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
                        conn.sendall(
                            f"227 Entering Passive Mode ({host_parts[0]},{host_parts[1]},{host_parts[2]},{host_parts[3]},{p1},{p2})\r\n".encode()
                        )
                        try:
                            conn_pasv, addr_pasv = pasv_sock.accept()
                            print(f"[+] Connection from {addr}")
                            response_pasv = RESPONSES.get(cmd, default_handler)(
                                arg or ""
                            )
                        except socket.error as e:
                            print("[-] Client handler error:", e)
                        finally:
                            continue
                    if cmd == "LIST":
                        if not logged_in:
                            conn.sendall(b"530 Not logged in.\r\n")
                            continue
                        response = (
                            subprocess.check_output(["ls", "-l", FTP_ROOT]) + b"\r\n"
                        )

                        if "conn_pasv" in locals():
                            conn.sendall(
                                b"150 Opening data connection for directory list\r\n"
                            )
                            conn_pasv.sendall(response)
                            conn_pasv.close()
                            conn.sendall(b"226 Transfer complete.\r\n")
                            continue
                        elif "active_dst_port" in locals():
                            active_socket = self.connect_active(
                                active_dst_ip, active_dst_port
                            )
                            conn.sendall(
                                b"150 Opening data connection for directory list\r\n"
                            )
                            active_socket.sendall(response)
                            active_socket.close()
                            conn.sendall(b"226 Transfer complete.\r\n")
                            continue
                        else:
                            conn.sendall(b"425 Can't open data connection\r\n")
                            continue

                    if cmd == "STOR":
                        if not logged_in:
                            conn.sendall(b"530 Not logged in.\r\n")
                            continue
                        file_path = os.path.realpath(os.path.join(FTP_ROOT, arg2))
                        if not file_path.startswith(FTP_ROOT):
                            conn.sendall(b"550 Access denied\r\n")
                            continue
                        try:
                            with open(file_path, "wb") as f:
                                conn.sendall(
                                    b"150 Opening data connection for file upload\r\n"
                                )

                                if "active_dst_port" in locals():
                                    active_socket = self.connect_active(
                                        active_dst_ip, active_dst_port
                                    )
                                    try:
                                        while chunk := active_socket.recv(1024):
                                            f.write(chunk)
                                    finally:
                                        active_socket.close()
                                    conn.sendall(b"226 Transfer complete\r\n")
                                    continue

                                elif "conn_pasv" in locals() and conn_pasv:
                                    try:
                                        while chunk := conn_pasv.recv(1024):
                                            f.write(chunk)
                                    finally:
                                        conn_pasv.close()
                                    conn.sendall(b"226 Transfer complete\r\n")
                                    continue

                                else:
                                    conn.sendall(b"425 Can't open data connection\r\n")
                                    continue

                        except Exception:
                            conn.sendall(b"550 Failed to store file\r\n")
                            continue

                    if cmd == "RETR":
                        if not logged_in:
                            conn.sendall(b"530 Not logged in.\r\n")
                            continue
                        file_path = os.path.realpath(os.path.join(FTP_ROOT, arg))
                        if not file_path.startswith(FTP_ROOT):
                            conn.sendall(b"550 Access denied\r\n")
                            continue
                        try:
                            with open(file_path, "rb") as f:
                                conn.sendall(
                                    b"150 Opening data connection for file transfer\r\n"
                                )

                                if "active_dst_port" in locals():
                                    active_socket = self.connect_active(
                                        active_dst_ip, active_dst_port
                                    )
                                    try:
                                        while chunk := f.read(1024):
                                            if self.transfer_type.upper() == "A":
                                                chunk = chunk.replace(b"\n", b"\r\n")
                                            elif self.transfer_type.upper() == "E":
                                                chunk = chunk.decode(
                                                    "utf-8", errors="replace"
                                                ).encode("cp500")
                                            active_socket.sendall(chunk)
                                    finally:
                                        active_socket.close()
                                    conn.sendall(b"226 Transfer complete\r\n")
                                    continue
                                elif "conn_pasv" in locals() and conn_pasv:
                                    try:
                                        while chunk := f.read(1024):
                                            if self.transfer_type.upper() == "A":
                                                chunk = chunk.replace(b"\n", b"\r\n")
                                            elif self.transfer_type.upper() == "E":
                                                chunk = chunk.decode(
                                                    "utf-8", errors="replace"
                                                ).encode("cp500")
                                            self.conn_pasv.sendall(chunk)
                                    finally:
                                        self.conn_pasv.close()
                                    conn.sendall(b"226 Transfer complete\r\n")
                                    continue
                                else:
                                    conn.sendall(b"425 Can't open data connection\r\n")
                                    continue

                        except FileNotFoundError:
                            conn.sendall(b"550 File not found\r\n")

                    # Send if not in either of the cases
                    conn.sendall(response.encode())
            elif self.server_port == 80:
                while True:
                    data = conn.recv(1024).decode(errors="ignore")
                    if not data:
                        break
                    self.write_logs(addr, data)
                    if data.upper().startswith("GET /"):
                        with (
                            open("./templates/80/default_headers", "r") as header,
                            open("./templates/80/default_page", "r") as body,
                        ):
                            headers = header.read()
                            bodies = body.read()
                            resp = f"{headers}Content-Length: {len(bodies.encode())}\r\n\r\n{bodies}"
                        conn.sendall(resp.encode())
                    elif data.upper().startswith("GET"):
                        with open("./templates/80/404", "r") as resp:
                            conn.sendall(resp.read().encode())
                    elif data.upper().startswith("POST"):
                        with (
                            open("./templates/80/default_headers", "r") as header,
                            open("./templates/80/incorrect_password", "r") as body,
                        ):
                            headers = header.read()
                            bodies = body.read()
                            resp = f"{headers}Content-Length: {len(bodies.encode())}\r\n\r\n{bodies}"
                        conn.sendall(resp.encode())

                    elif data.upper().startswith("HEAD"):
                        with open("./templates/80/default_headers", "r") as header:
                            conn.sendall(header.read().encode())
                    else:
                        with open("./templates/80/400", "r") as resp:
                            conn.sendall(resp.read().encode())
            else:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    conn.sendall(default)

    def write_logs(self, addr, data):
        """Write logs into JSON file"""

        action = {
            "time": datetime.datetime.now().isoformat(),
            "remote_ip": addr[0],
            "remote_port": addr[1],
            "local_port": self.server_port,
            "data": data,
        }
        os.makedirs(LOG_PATH + str(self.server_port), exist_ok=True)
        with open(self.filename, "a") as file:
            json.dump(action, file)
            file.write("\n")
        print(f"[+] Log saved to {self.filename}")


def main():
    os.makedirs(FTP_ROOT, exist_ok=True)
    parser = argparse.ArgumentParser(
        description="Simple honeypot for production", add_help=False
    )
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="Show the help menu and exit",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        nargs="*",
        choices=[21, 80],
        help="Ports that honeypot will listen to (Default: [21, 80])",
    )
    parser.add_argument(
        "-H",
        "--host",
        type=str,
        nargs="*",
        help="Interfaces honeypot will listen to (Default: 0.0.0.0 = All Interfaces)",
    )
    args = parser.parse_args()

    hosts = (
        args.host
        if isinstance(args.host, list)
        else [args.host]
        if args.host
        else ["0.0.0.0"]
    )
    ports = (
        args.port
        if isinstance(args.port, list)
        else [args.port]
        if args.port
        else [21, 80]
    )

    for h in hosts:
        hp_instance = Honeypot(host=h)
        for p in ports:
            t = threading.Thread(
                target=hp_instance.listen_connection,
                args=(p,),  # port is passed as positional argument
                daemon=True,
            )
            t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[+] Stopping Honeypot..")
        sys.exit(0)


if __name__ == "__main__":
    main()
