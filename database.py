import sqlite3

class Database:
    def __init__(self, db_path="subhunter.db"):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TEXT DEFAULT (datetime('now')),
                total_discovered INTEGER DEFAULT 0,
                total_live INTEGER DEFAULT 0,
                total_dead INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT,
                status INTEGER,
                tech TEXT,
                score INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.commit()
        conn.close()

    def save_scan(self, domain, discovered, live, dead, user_id=None):
        conn = self.get_connection()
        cursor = conn.execute("""
            INSERT INTO scans (domain, total_discovered, total_live, total_dead, user_id)
            VALUES (?, ?, ?, ?, ?)
        """, (domain, discovered, live, dead, user_id))
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def save_finding(self, scan_id, url, status, tech, score):
        conn = self.get_connection()
        conn.execute("""
            INSERT INTO findings (scan_id, url, status, tech, score)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, url, status, tech, score))
        conn.commit()
        conn.close()

    def get_all_scans(self):
        conn = self.get_connection()
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC"
        ).fetchall()
        conn.close()
        return rows

    def get_findings(self, scan_id):
        conn = self.get_connection()
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        conn.close()
        return rows

    def create_user(self, username, password_hash):
        try:
            conn = self.get_connection()
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            print("Username already exists")
            return False

    def get_user(self, username):
        conn = self.get_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        return user

    def get_user_scans(self, user_id):
        conn = self.get_connection()
        rows = conn.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC",
            (user_id,)
        ).fetchall()
        conn.close()
        return rows

    def update_password(self, username, new_hash):
        conn = self.get_connection()
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (new_hash, username)
        )
        conn.commit()
        conn.close()


if __name__ == "__main__":
    db = Database()
    scan_id = db.save_scan("hackerone.com", 12, 2, 10)
    print(f"[+] Scan saved with ID: {scan_id}")

    db.save_finding(scan_id, "https://api.hackerone.com", 200, "cloudflare", 100)
    db.save_finding(scan_id, "https://www.hackerone.com", 200, "cloudflare", 67)
    print("[+] Findings saved")

    scans = db.get_all_scans()
    for scan in scans:
        print(dict(scan))

