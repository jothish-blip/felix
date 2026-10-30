#!/usr/bin/env python3
"""
SSTI & Command Injection / Arithmetic Evaluation Mock Server
Part of FELIX v3.0 Ground-Truth Testing Suite (Subphase 2.5)

Provides:
- Vulnerable Jinja2 endpoint: /render (GET/POST) evaluating template expressions dynamically.
- Defended endpoint: /safe (GET/POST) safely reflecting template expressions without evaluation.
- Healthcheck endpoint: /health (GET).
"""

import sys
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import html
import jinja2

class SSTIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress noisy standard request logs during benchmark runs
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/health" or path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","engine":"jinja2-benchmark"}')
            return

        if path == "/render":
            template_code = query.get("template", query.get("name", ["World"]))[0]
            try:
                # Insecure template evaluation: compiling user input directly into a Jinja2 template
                rendered = jinja2.Template(template_code).render()
                body = f"""<!DOCTYPE html>
<html>
<head><title>SSTI Vulnerable Lab</title></head>
<body>
<h1>Template Evaluation Service</h1>
<div class="output">{rendered}</div>
</body>
</html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                err_body = f"<html><body><h1>Template Error</h1><pre>{html.escape(str(e))}</pre></body></html>"
                self.wfile.write(err_body.encode("utf-8"))
            return

        if path == "/safe":
            raw_input = query.get("template", query.get("name", ["World"]))[0]
            # Defended: Using standard template context variables; expressions are not evaluated
            rendered = jinja2.Template("Hello, {{ user_input }}!").render(user_input=raw_input)
            body = f"""<!DOCTYPE html>
<html>
<head><title>SSTI Defended Lab</title></head>
<body>
<h1>Safe Template Output</h1>
<div class="output">{html.escape(rendered)}</div>
</body>
</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len).decode("utf-8", errors="replace")
        form_data = urllib.parse.parse_qs(post_body)

        if path == "/render":
            template_code = form_data.get("template", form_data.get("name", ["World"]))[0]
            try:
                rendered = jinja2.Template(template_code).render()
                body = f"""<!DOCTYPE html>
<html>
<head><title>SSTI Vulnerable Lab</title></head>
<body>
<h1>Template Evaluation Service</h1>
<div class="output">{rendered}</div>
</body>
</html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"<html><body>Error: {html.escape(str(e))}</body></html>".encode("utf-8"))
            return

        if path == "/safe":
            raw_input = form_data.get("template", form_data.get("name", ["World"]))[0]
            rendered = jinja2.Template("Hello, {{ user_input }}!").render(user_input=raw_input)
            body = f"""<!DOCTYPE html>
<html>
<head><title>SSTI Defended Lab</title></head>
<body>
<h1>Safe Template Output</h1>
<div class="output">{html.escape(rendered)}</div>
</body>
</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

def main():
    parser = argparse.ArgumentParser(description="FELIX Phase 2.5 SSTI Benchmark Lab")
    parser.add_argument("--port", type=int, default=5050, help="Port to listen on (default: 5050)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    args = parser.parse_args()

    server_address = (args.host, args.port)
    httpd = HTTPServer(server_address, SSTIHandler)
    print(f"SSTI Jinja2 Benchmark Server running at http://{args.host}:{args.port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()

if __name__ == "__main__":
    main()
