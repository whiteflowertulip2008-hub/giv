import http.server
import json
import os
import csv
import html
import hmac
from datetime import datetime
from urllib.parse import urlparse

HOST = "0.0.0.0"
PORT = 800

VALID_CODE = "NIKE-2026-IITD"

ADMIN_USER = "admin"
ADMIN_PASSWORD = "admin2323"

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
STORE_FILE = os.path.join(ROOT_DIR, "store.csv")
WEAK_PASSWORDS_FILE = os.path.join(ROOT_DIR, "weak.txt")

CSV_FIELDS = [
    "timestamp",
    "username",
    "invite_code",
    "access_provided",
    "code_status",
    "agree_status"
]

SEQUENCES = (
    "01234567890",
    "09876543210",
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "qwertyuiopasdfghjklzxcvbnm",
)


def load_weak_passwords():
    if not os.path.exists(WEAK_PASSWORDS_FILE):
        print(f"[WARNING] {WEAK_PASSWORDS_FILE} not found. Running without wordlist.")
        return set()

    with open(WEAK_PASSWORDS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        return {line.strip().lower() for line in f if line.strip()}


WEAK_PASSWORDS = load_weak_passwords()


def validate_password(value):
    lower = value.lower()

    if lower in WEAK_PASSWORDS:
        return False, "Incorrect password."

    if len(value) < 8:
        return False, "Incorrect password."

    if len(set(lower)) == 1:
        return False, "Incorrect password."

    if any(lower in seq for seq in SEQUENCES):
        return False, "Incorrect password."

    if value.isdigit():
        return False, "Incorrect password."

    return True, ""


def initialize_csv():
    if not os.path.exists(STORE_FILE):
        with open(STORE_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()


class NikeHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT_DIR, **kwargs)

    def authenticate_admin(self):

        auth = self.headers.get("Authorization", "")

        if not auth.startswith("Basic "):
            return False

        import base64

        try:
            decoded = base64.b64decode(auth[6:]).decode()
            username, password = decoded.split(":", 1)

            return (
                hmac.compare_digest(username, ADMIN_USER)
                and ADMIN_PASSWORD is not None
                and hmac.compare_digest(password, ADMIN_PASSWORD)
            )

        except Exception:
            return False

    def do_GET(self):

        if urlparse(self.path).path == "/admin":

            if not self.authenticate_admin():
                self.send_response(401)
                self.send_header(
                    "WWW-Authenticate",
                    'Basic realm="Nike Admin Dashboard"'
                )
                self.end_headers()
                return

            self.show_admin_dashboard()
            return

        super().do_GET()

    def load_records(self):

        records = []

        initialize_csv()

        with open(STORE_FILE, "r", newline="", encoding="utf-8") as f:

            reader = csv.DictReader(f)

            for row in reader:

                records.append({
                    "timestamp": row.get("timestamp", ""),
                    "username": row.get("username", ""),
                    "accessKey": row.get("access_provided", ""),
                    "invite": row.get("invite_code", ""),
                    "code": row.get("code_status", ""),
                    "agreement": row.get("agree_status", "")
                })

        return records

    def show_admin_dashboard(self):

        records = self.load_records()

        total = len(records)

        rows = ""

        for r in reversed(records):

            rows += f"""
            <tr>
                <td class="username">
                    {html.escape(r["username"])}
                </td>

                <td class="access">
                    {html.escape(r["accessKey"])}
                </td>

                <td class="timestamp">
                    {html.escape(r["timestamp"])}
                </td>
            </tr>
            """

        if not rows:
            rows = """
            <tr>
                <td colspan="3" class="empty">
                    No submissions yet.
                </td>
            </tr>
            """

        page = f"""
        <!DOCTYPE html>
        <html>
        <head>

            <title>NIKE Admin Dashboard</title>

            <meta name="viewport"
                  content="width=device-width, initial-scale=1">

            <style>

                * {{
                    box-sizing: border-box;
                }}

                body {{
                    margin: 0;
                    padding: 35px;
                    background: #f5f5f5;
                    color: #171717;
                    font-family: Arial, sans-serif;
                }}

                .container {{
                    max-width: 1200px;
                    margin: auto;
                }}

                .header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    flex-wrap: wrap;
                    gap: 15px;
                    margin-bottom: 30px;
                }}

                h1 {{
                    font-size: 28px;
                    margin: 0;
                    letter-spacing: 1px;
                }}

                .subtitle {{
                    color: #777;
                    margin-top: 8px;
                }}

                .stats {{
                    background: white;
                    padding: 25px;
                    border-radius: 12px;
                    margin-bottom: 25px;
                }}

                .stats h2 {{
                    font-size: 32px;
                    margin: 0;
                }}

                .stats p {{
                    color: #777;
                    margin-bottom: 0;
                }}

                .table-container {{
                    background: white;
                    padding: 25px;
                    border-radius: 12px;
                    box-shadow: 0 2px 10px #00000008;
                }}

                .table-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    gap: 15px;
                    flex-wrap: wrap;
                    margin-bottom: 20px;
                }}

                .table-header h3 {{
                    margin: 0;
                }}

                input {{
                    padding: 12px 15px;
                    border: 1px solid #ddd;
                    border-radius: 7px;
                    outline: none;
                    width: 260px;
                    max-width: 100%;
                }}

                input:focus {{
                    border-color: black;
                }}

                .table-scroll {{
                    overflow-x: auto;
                }}

                table {{
                    width: 100%;
                    border-collapse: collapse;
                    text-align: left;
                    white-space: nowrap;
                }}

                th {{
                    background: #fafafa;
                    color: #777;
                    font-size: 12px;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }}

                th, td {{
                    padding: 17px 15px;
                    border-bottom: 1px solid #eee;
                }}

                td {{
                    font-size: 14px;
                }}

                .username {{
                    font-weight: 600;
                }}

                .access {{
                    color: #16803c;
                    font-weight: 600;
                }}

                .timestamp {{
                    color: #777;
                }}

                tr:hover {{
                    background: #fafafa;
                }}

                .empty {{
                    text-align: center;
                    padding: 40px;
                    color: #888;
                }}

                .refresh {{
                    background: black;
                    color: white;
                    padding: 12px 20px;
                    border-radius: 7px;
                    text-decoration: none;
                    font-size: 13px;
                }}

                @media(max-width: 600px) {{
                    body {{
                        padding: 15px;
                    }}

                    .table-container {{
                        padding: 15px;
                    }}

                    input {{
                        width: 100%;
                    }}
                }}

            </style>

        </head>

        <body>

            <div class="container">

                <div class="header">

                    <div>
                        <h1>NIKE ADMIN</h1>

                        <div class="subtitle">
                            Giveaway Submission Dashboard
                        </div>
                    </div>

                    <a href="/admin" class="refresh">
                        Refresh Data
                    </a>

                </div>

                <div class="stats">

                    <h2>{total}</h2>
                    <p>Total Submissions</p>

                </div>

                <div class="table-container">

                    <div class="table-header">

                        <h3>All Submissions</h3>

                        <input
                            type="text"
                            id="searchInput"
                            placeholder="Search username..."
                            onkeyup="searchTable()"
                        >

                    </div>

                    <div class="table-scroll">

                        <table id="submissionTable">

                            <thead>
                                <tr>
                                    <th>Instagram Username</th>
                                    <th>Access Status</th>
                                    <th>Submission Time</th>
                                </tr>
                            </thead>

                            <tbody>
                                {rows}
                            </tbody>

                        </table>

                    </div>

                </div>

            </div>

            <script>

                function searchTable() {{

                    let input = document
                        .getElementById("searchInput")
                        .value.toLowerCase();

                    let rows = document
                        .getElementById("submissionTable")
                        .getElementsByTagName("tr");

                    for (let i = 1; i < rows.length; i++) {{

                        let username = rows[i]
                            .getElementsByTagName("td")[0];

                        if (username) {{

                            let text = username.textContent.toLowerCase();

                            rows[i].style.display =
                                text.includes(input) ? "" : "none";

                        }}

                    }}

                }}

            </script>

        </body>
        </html>
        """

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        self.wfile.write(page.encode("utf-8"))

    def do_POST(self):

        if urlparse(self.path).path != "/submit":
            self.send_error(404)
            return

        try:

            length = int(self.headers.get("Content-Length", 0))

            if length <= 0 or length > 10000:
                self.send_error(400, "Invalid request size")
                return

            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)

            username = str(data.get("instagram", "")).strip()
            invite_code = str(data.get("inviteCode", "")).strip()
            agreed = data.get("agreed", False)

            if not username or len(username) > 100:
                self.send_error(400, "Invalid username")
                return

            if len(invite_code) > 100:
                self.send_error(400, "Invalid invite code")
                return

            if not isinstance(agreed, bool):
                self.send_error(400, "Invalid agreement value")
                return

            access_provided = str(data.get("accessKey", "")).strip()

            is_valid_pw, pw_error = validate_password(access_provided)
            if not is_valid_pw:
                resp = {
                    "success": False,
                    "message": pw_error
                }
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(json.dumps(resp).encode("utf-8"))
                code_status = (
                                "CORRECT"
                                if invite_code == VALID_CODE
                                else "WRONG"
                            )
                
                agree_status = (
                                "AGREED"
                                if agreed
                                else "NOT_AGREED"
                            )
                
                timestamp = datetime.now().strftime(
                                "%Y-%m-%d %H:%M:%S"
                            )
                
                initialize_csv()
                
                with open(
                                STORE_FILE, "a", newline="", encoding="utf-8"
                            ) as f:
                            writer = csv.DictWriter(
                                    f,
                                    fieldnames=CSV_FIELDS
                                )
                            writer.writerow({
                                    "timestamp": timestamp,
                                    "username": username,
                                    "invite_code": invite_code,
                                    "access_provided": access_provided,
                                    "code_status": code_status,
                                    "agree_status": agree_status
                                })
                
                print(f"[STORED] {timestamp} | {username}")
                return

            code_status = (
                "CORRECT"
                if invite_code == VALID_CODE
                else "WRONG"
            )

            agree_status = (
                "AGREED"
                if agreed
                else "NOT_AGREED"
            )

            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            initialize_csv()

            with open(
                STORE_FILE, "a", newline="", encoding="utf-8"
            ) as f:

                writer = csv.DictWriter(
                    f,
                    fieldnames=CSV_FIELDS
                )

                writer.writerow({
                    "timestamp": timestamp,
                    "username": username,
                    "invite_code": invite_code,
                    "access_provided": access_provided,
                    "code_status": code_status,
                    "agree_status": agree_status
                })

            print(f"[STORED] {timestamp} | {username}")

            if code_status == "CORRECT" and agree_status == "AGREED":

                resp = {
                    "success": True,
                    "message": (
                        "Thank you for signing up for the giveaway!"
                    )
                }

            else:

                reasons = []

                if code_status == "WRONG":
                    reasons.append("Invalid invite code")

                if agree_status == "NOT_AGREED":
                    reasons.append("You must agree to the terms")

                resp = {
                    "success": False,
                    "message": " & ".join(reasons) + ". Your entry has failed."
                }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

            self.wfile.write(json.dumps(resp).encode("utf-8"))

        except (ValueError, json.JSONDecodeError):
            self.send_error(400, "Invalid JSON request")

    def do_OPTIONS(self):

        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


if __name__ == "__main__":

    if not ADMIN_PASSWORD:
        raise SystemExit(
            "Set ADMIN_PASSWORD before starting the server."
        )

    initialize_csv()

    server = http.server.HTTPServer((HOST, PORT), NikeHandler)

    print(f"""
====================================================
             NIKE GIVEAWAY SERVER
====================================================

Landing Page : http://localhost:{PORT}/index.html
Signup Page  : http://localhost:{PORT}/signup.html
Admin Panel  : http://localhost:{PORT}/admin
Database     : store.csv
Weak List    : weak.txt ({len(WEAK_PASSWORDS)} loaded)

Admin User   : {ADMIN_USER}

====================================================
""")

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        server.server_close()
