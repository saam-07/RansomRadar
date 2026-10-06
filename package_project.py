"""
Utility script to create a clean, pristine zip package of the AdaptShield codebase,
excluding caches, virtualenvs, and temporary files.
"""
import os
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
OUTPUT_ZIP = ROOT_DIR.parent / "adaptshield.zip"

EXCLUDE_DIRS = {
    "__pycache__", ".pytest_cache", ".venv", "venv", ".git", ".idea", ".vscode",
    "adaptshield.egg-info", "scratch"
}
EXCLUDE_EXTS = {".pyc", ".pyo", ".pyd", ".DS_Store"}


def make_clean_zip(output_path: Path):
    print(f"Packaging {ROOT_DIR} -> {output_path}...")
    file_count = 0
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(ROOT_DIR):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.endswith(".egg-info")]
            
            rel_root = Path(root).relative_to(ROOT_DIR)
            
            # Ensure empty directories like results/raw, results/processed are preserved
            if rel_root != Path("."):
                zf.write(root, str(rel_root))

            for file in sorted(files):
                if file.endswith(".zip") or file == "package_project.py":
                    continue
                if any(file.endswith(ext) for ext in EXCLUDE_EXTS):
                    continue
                
                file_path = Path(root) / file
                arcname = str(file_path.relative_to(ROOT_DIR))
                zf.write(file_path, arcname)
                file_count += 1
                print(f"  + {arcname}")

    print(f"\nSuccessfully packaged {file_count} files into {output_path} ({os.path.getsize(output_path)} bytes).")


if __name__ == "__main__":
    make_clean_zip(OUTPUT_ZIP)
