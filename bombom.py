#!/usr/bin/env python3
"""
BomBom - System Package Information Collector

This script collects information about installed software packages and system
components to create a Software Bill of Materials (SBOM). It gathers data from:

Package Managers:
- dpkg (Debian packages)
- pip (Python packages)
- pipx (Isolated Python packages)
- uvx (uv-managed Python packages)
- flatpak (Containerized applications)
- snap (Universal Linux packages)
- npm (Node.js packages)
- docker (Container images)

System Components:
- Firefox version
- Kernel version
- Evolution version
- Chrome version
- VS Code version
- DBus services
- Systemd services

Usage:
  bombom.py -d DIR [-t]

Options:
  -d, --dir DIR  Directory to save SBOM files (required)
  -t, --tar      Output all files as tar archive to stdout

"""

import os
import subprocess
import json
from datetime import datetime
import shutil
import sys
import shlex
import argparse
import tarfile
from io import BytesIO
import time
import hashlib


def run_command(thecommand, shell=False):
    return run_command_x(thecommand, shell)["stdout"]

def runtime_command_version(thecommand):
    try:
        assert thecommand.startswith("/"), "Command must be an absolute path"
        cmd_result = subprocess.run([thecommand, "--version"], capture_output=True, text=True)
        return cmd_result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command {thecommand}: {e}", file=sys.stderr)

def run_command_x(thecommand, shell=False):
    """Run a command and return its output and executable hash"""
    if isinstance(thecommand, str):
        command = shlex.split(thecommand)
    else:
        command = thecommand
    assert isinstance(command, list)
    executable = command[0]
    full_exec = shutil.which(executable)
    result = {
        "executable": full_exec,
        "stdout": None,
        "hash": None,
        "version": None,
    }
    
    if full_exec is None:
        print(f"Skipping {executable} exec as it's not installed from {thecommand}", file=sys.stderr)
        return result

    result["version"] = runtime_command_version(full_exec)
        
    # Calculate SHA256 hash of the executable
    try:
        with open(full_exec, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
            result["hash"] = file_hash.hexdigest()
    except (IOError, OSError) as e:
        print(f"Error calculating hash for {full_exec}: {e}", file=sys.stderr)
        
    try:
        cmd_result = subprocess.run(command, capture_output=True, text=True, shell=shell, timeout=5)
        result["stdout"] = cmd_result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command {command}: {e}")
    except subprocess.TimeoutExpired as e:
        print(f"Command {command} timed out: {e}")
        
    return result

def save_to_file(filename, content):
    """Save content to a file, ensuring there's a newline at the end"""
    if not content:
        return
    if not content.endswith('\n'):
        content += '\n'
    with open(filename, 'w') as f:
        f.write(content)

def append_if_not_exists(filename, content):
    """Append content to file if the content doesn't already exist"""
    try:
        with open(filename, 'r') as f:
            if content in f.read():
                return
    except FileNotFoundError:
        pass
    
    with open(filename, 'a') as f:
        date = datetime.now().strftime('%Y%m%d')
        f.write(f"{date} {content}\n")

def pip_system():
    """List installed packages in the site-packages directory"""
    try:
        res = []
        import site
        import pkg_resources

        # Get the site-packages directory
        site_packages = site.getsitepackages()

        for path in site_packages:
            # print(f"Packages in {path}:")
            for dist in pkg_resources.find_distributions(path):
                res.append(str(dist).replace(" ","=="))
        return 'text/plain','\n'.join(res)
    except Exception as e:
        print(f"Error importing modules: {e}", file=sys.stderr)


def save_all_commands(dir_path, commands):
    """Save command outputs to files in the specified directory
    
    Args:
        dir_path (str): Directory to save files
        commands (list): List of tuples containing (filename, command, shell_flag)
    """
    audit = {}
    for filename, command, shell in commands:
        trail = save_command_output(os.path.join(dir_path,filename), command, shell)
        if trail:
            del trail["stdout"]
            audit[trail["executable"]] = trail
    save_to_file(os.path.join(dir_path,"path-hashes.json"), json.dumps(audit, indent=2))
def format(mimetype, output):
    if mimetype == 'text/plain':
        return output
    raise ValueError(f"Unsupported mimetype {mimetype}")

def save_command_output(filename, command, shell):
    if callable(command):
        mimetype, output = command()
        if output:
            save_to_file(filename, format(mimetype, output))
        return
    executable = shlex.split(command)[0]
    if shutil.which(executable) is None:
        print(f"Skipping {command} command as it's not installed", file=sys.stderr)
        return
    output = run_command_x(command, shell=shell)
    # print(f"Saving {output['executable']} with hash {output['hash']}")
    if output:
        save_to_file(filename, output["stdout"])
    return output

def create_tar_from_files(files):
    """Create a tar file from a list of (filename, content) tuples
    
    Args:
        files (list): List of tuples containing (filename, content)
    
    Returns:
        BytesIO: In-memory tar archive
    """
    tar_buffer = BytesIO()
    current_time = time.time()
    
    with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
        for fname, content in files:
            # Create a BytesIO object with the content
            data = BytesIO(content.encode('utf-8'))
            
            # Create a TarInfo object with file info
            info = tarfile.TarInfo(name=fname)
            info.size = len(data.getvalue())
            info.mtime = current_time  # Set modification time to current time
            
            # Reset the BytesIO position
            data.seek(0)
            
            # Add the file to the tar archive
            tar.addfile(info, data)
    
    # Reset buffer position to start
    tar_buffer.seek(0)
    return tar_buffer

def parse_args():
    parser = argparse.ArgumentParser(description='Save system package information to SBOM files')
    parser.add_argument('--dir', '-d', 
                    required=True,
                    help='Directory where to save the SBOM files')
    parser.add_argument('--tar', '-t',
                    action='store_true',
                    help='Output all files as tar archive to stdout')
    return parser.parse_args()

def main():
    # Directory setup
    args = parse_args()
    DIR = args.dir
    os.makedirs(DIR, exist_ok=True)

    # Define all commands and their output files
    commands = [
        ("packages-debian.txt", "dpkg --get-selections", False),
        ("dpkg.txt", "dpkg -l", False),
        ("pip-system.txt", pip_system, True),
        ("pip-user.txt", "pip3 freeze --user", False),
        ("pipx-list.txt", "pipx list", False),
        ("uvx-list.txt", "uv tool list", False),
        ("flatpak.txt", "flatpak list", False),
        ("snap.txt", "snap list", False),
        ("npm.txt", "npm list -g", False),
    ]
    
    # Execute all commands and save outputs
    save_all_commands(DIR, commands)

    # Special cases that need different handling
    # Docker
    docker_output = run_command("docker images --format 'json'")
    docker_data = []
    if docker_output:
        for docker_json in docker_output.splitlines(): 
            # print(docker_output)
            docker_json = json.loads(docker_json)
            if "CreatedSince" in docker_json:    
                del docker_json["CreatedSince"] 
            docker_data.append(docker_json)
    save_to_file(f"{DIR}/docker.txt", json.dumps(docker_data, indent=2))

    # Python
    python_version = run_command("python --version")
    if python_version:
        append_if_not_exists(f"{DIR}/python-versions.txt", python_version)
        
    # Firefox
    firefox_version = run_command("firefox --version")
    if firefox_version:
        append_if_not_exists(f"{DIR}/firefox-versions.txt", firefox_version)

    # Kernel
    kernel_info = run_command("uname -a")
    if kernel_info:
        append_if_not_exists(f"{DIR}/kernel.txt", kernel_info)

    # Evolution
    evolution_version = run_command("flatpak run org.gnome.Evolution --version")
    if evolution_version:
        append_if_not_exists(f"{DIR}/evolution.txt", evolution_version)

    # Chrome
    chrome_version = run_command("chrome --version")
    if chrome_version:
        append_if_not_exists(f"{DIR}/chrome.txt", chrome_version)

    # VS Code
    code_version = run_command("code --version")
    if code_version:
        append_if_not_exists(f"{DIR}/code.txt", code_version)

    # DBus
    dbus_command = "dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames"
    dbus_output = run_command(dbus_command, shell=True)
    if dbus_output:
        # Filter out lines containing ":"
        filtered_output = '\n'.join(line for line in dbus_output.splitlines() if ':' not in line)
        save_to_file(f"{DIR}/dbus-system.txt", filtered_output)

    # Systemd services
    systemd_output = run_command("systemctl list-unit-files")
    if systemd_output:
        enabled_services = '\n'.join(line for line in systemd_output.splitlines() if 'enabled' in line)
        save_to_file(f"{DIR}/systemd-services.txt", enabled_services)

    # If tar option is specified, create and output tar archive
    if args.tar:
        tar_results(DIR)

def tar_results(dir):  
    # Create tar archive in memory with all files from DIR
    files_to_tar = []
    for filename in os.listdir(dir):
        filepath = os.path.join(dir, filename)
        if os.path.isfile(filepath):
            with open(filepath, 'r') as f:
                content = f.read()
                files_to_tar.append((filename, content))
    
    tar_buffer = create_tar_from_files(files_to_tar)
    # Save to file if needed
    sys.stdout.buffer.write(tar_buffer.getvalue())
        
if __name__ == "__main__":
    main()
