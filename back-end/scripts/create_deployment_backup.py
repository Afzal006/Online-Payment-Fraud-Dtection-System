"""
Deployment Freeze & Project Backup Utility for FraudShield AI.
Creates:
1. Complete sanitised project deployment archive (excluding .env, secrets, caches, temp files).
2. Standalone database backup of instance/fraud_detection.db.
"""

import os
import sys
import shutil
import zipfile
import sqlite3
from datetime import datetime

ROOT_DIR = os.path.abspath(".")
BACKUP_DIR = os.path.join(ROOT_DIR, "backups")
DB_BACKUP_DIR = os.path.join(BACKUP_DIR, "database")

EXCLUDE_PATTERNS = [
    ".env",
    "__pycache__",
    ".pytest_cache",
    ".git",
    "node_modules",
    "scratch",
    ".log",
    "backups",
    ".pyc",
]

def is_excluded(rel_path):
    parts = rel_path.replace("\\", "/").split("/")
    # Exact file match
    if rel_path == ".env" or parts[-1] == ".env":
        return True
    for part in parts:
        if part in ["__pycache__", ".pytest_cache", ".git", "node_modules", "scratch", "backups"]:
            return True
        if part.endswith(".pyc") or part.endswith(".log"):
            return True
    return False

def create_backups():
    os.makedirs(DB_BACKUP_DIR, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    db_source = os.path.join(ROOT_DIR, "instance", "fraud_detection.db")
    db_dest = os.path.join(DB_BACKUP_DIR, f"fraud_detection_freeze_{timestamp}.db")
    
    # 1. Database backup
    print("[*] Creating isolated database backup...")
    if os.path.exists(db_source):
        # Use sqlite3 online backup API for complete ACID consistency
        src_conn = sqlite3.connect(db_source)
        dst_conn = sqlite3.connect(db_dest)
        with dst_conn:
            src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()
        db_size_kb = os.path.getsize(db_dest) / 1024
        print(f"[+] Database backup created: {db_dest} ({db_size_kb:.2f} KB)")
    else:
        print("[-] Warning: instance/fraud_detection.db not found.")
        db_dest = None

    # 2. Project archive
    zip_path = os.path.join(BACKUP_DIR, f"fraudshield_ai_freeze_{timestamp}.zip")
    print(f"[*] Packaging sanitised deployment archive into: {zip_path}")
    
    included_files = []
    excluded_files = []
    
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(ROOT_DIR):
            # Prune directories in-place for performance
            dirs[:] = [d for d in dirs if not is_excluded(os.path.relpath(os.path.join(root, d), ROOT_DIR))]
            
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, ROOT_DIR)
                
                if is_excluded(rel_path):
                    excluded_files.append(rel_path)
                    continue
                
                zipf.write(full_path, rel_path)
                included_files.append(rel_path)

    # 3. Verification
    print("[*] Verifying archive integrity and absence of secrets...")
    with zipfile.ZipFile(zip_path, "r") as check_zip:
        namelist = check_zip.namelist()
        for name in namelist:
            parts = name.replace("\\", "/").split("/")
            if ".env" in parts and not name.endswith(".env.example"):
                raise ValueError(f"CRITICAL: Found secret file {name} in deployment archive!")
            for part in parts:
                if part in ["__pycache__", ".pytest_cache", "scratch", ".git"]:
                    raise ValueError(f"Warning: Found excluded folder file {name} in archive!")

    archive_size_mb = os.path.getsize(zip_path) / (1024 * 1024)
    print(f"[+] Verified: Archive contains {len(included_files)} files ({archive_size_mb:.2f} MB)")
    print(f"[+] Excluded {len(excluded_files)} files/artifacts safely.")
    
    return {
        "archive_path": zip_path,
        "archive_size_mb": archive_size_mb,
        "db_backup_path": db_dest,
        "db_size_kb": db_size_kb if db_dest else 0,
        "included_count": len(included_files),
        "excluded_count": len(excluded_files),
    }

if __name__ == "__main__":
    res = create_backups()
    print("\nBACKUP RESULT SUMMARY:")
    print(f"  Archive: {res['archive_path']}")
    print(f"  DB Backup: {res['db_backup_path']}")
    print(f"  Archive Size: {res['archive_size_mb']:.2f} MB")
