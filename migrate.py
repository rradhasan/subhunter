import sqlite3

def migrate():
    conn = sqlite3.connect("subhunter.db")

    cursor = conn.execute("PRAGMA table_info(scans)")
    columns = [row[1] for row in cursor.fetchall()]

    if "user_id" not in columns:
        print("[*] Adding user_id column to scans table...")
        conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")
        conn.commit()
        print("[+] Migration Complete")
    else:
        print("[*] user_id column already exists - skipping")

    conn.close()


if __name__ == "__main__":
    migrate()