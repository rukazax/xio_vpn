#!/usr/bin/env python3
"""Temporary diagnostic HTTP, bound only to VPN addresses, never public IP."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, threading, signal
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        data = (b'x1o-vps-payload-' * 65536) if self.path == '/payload' else json.dumps({'marker':'x1o-real-debian-vps','client':self.client_address[0],'server':self.server.server_address[0]}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Content-Type', 'application/octet-stream' if self.path == '/payload' else 'application/json')
        self.end_headers()
        self.wfile.write(data)
servers = [ThreadingHTTPServer((address,8080),Handler) for address in ['10.77.0.1','10.78.0.1']]
for server in servers: threading.Thread(target=server.serve_forever,daemon=True).start()
signal.pause()
