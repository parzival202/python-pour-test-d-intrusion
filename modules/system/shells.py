"""
system/shells.py
Helper functions to build shell commands for lab VMs (demo only).
"""
def build_reverse_shell_cmd(ip, port):
    # simple echo as a demo, replace with safe operations in lab
    return f"echo 'connect to {ip}:{port}'"
