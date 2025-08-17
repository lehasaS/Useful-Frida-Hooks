import os
import sys
import ast
import subprocess
import venv

VENV_DIR = "frida-environment"

# --- Step 1: Generate requirements.txt ---
EXCLUDE_MODULES = set(sys.builtin_module_names)

def find_python_files(root_dir="."):
    py_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for f in filenames:
            if f.endswith(".py"):
                py_files.append(os.path.join(dirpath, f))
    return py_files

def extract_imports_from_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=file_path)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                imports.add(n.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split('.')[0])
    return imports

def generate_requirements():
    py_files = find_python_files()
    all_imports = set()
    for file_path in py_files:
        all_imports.update(extract_imports_from_file(file_path))
    external_modules = sorted([m for m in all_imports if m not in EXCLUDE_MODULES])
    with open("requirements.txt", "w", encoding="utf-8") as f:
        for mod in external_modules:
            f.write(f"{mod}\n")
    print(f"[+] Generated requirements.txt with {len(external_modules)} modules.")

# --- Step 2: Create virtual environment ---
def create_venv():
    if not os.path.exists(VENV_DIR):
        print(f"[+] Creating virtual environment at {VENV_DIR}")
        venv.EnvBuilder(with_pip=True).create(VENV_DIR)
    else:
        print(f"[+] Virtual environment already exists at {VENV_DIR}")

def install_requirements():
    pip_path = os.path.join(VENV_DIR, "Scripts" if os.name == "nt" else "bin", "pip")
    print("[+] Installing requirements...")
    subprocess.check_call([pip_path, "install", "-r", "requirements.txt"])

def open_shell():
    activate = os.path.join(VENV_DIR, "Scripts" if os.name == "nt" else "bin", "activate")
    print(f"[+] Virtual environment ready. To activate manually: source {activate}")
    if os.name == "nt":
        subprocess.call(["cmd.exe", "/k", activate])
    else:
        subprocess.call(["bash", "--rcfile", activate])

if __name__ == "__main__":
    generate_requirements()
    create_venv()
    install_requirements()
    open_shell()
