import json
import subprocess
import uuid
import platform

SBOM_PATH = "/home/arch/sbom/sbom.json"

with open(SBOM_PATH, "r") as f:
    data = json.load(f)

host_uuid = str(uuid.uuid4())

os_name = platform.system()

kernel = platform.release()

insert_os = f"""
INSERT INTO os_info
(host_uuid, hostname, os_name, kernel_version)
VALUES
('{host_uuid}', 'archlinux', '{os_name}', '{kernel}');
"""

subprocess.run([
    "docker", "exec", "-i",
    "postgres",
    "psql",
    "-U", "monitor",
    "-d", "monitoring",
    "-q",
    "-c",
    insert_os
])

result = subprocess.check_output([
    "docker", "exec", "-i",
    "postgres",
    "psql",
    "-U", "monitor",
    "-d", "monitoring",
    "-t",
    "-A",
    "-c",
    "SELECT MAX(id) FROM os_info;"
])

os_id = result.decode().strip()

components = data.get("components", [])

for comp in components:

    name = comp.get("name")
    version = comp.get("version")

    if not name:
        continue

    if not version:
        version = "unknown"

    insert_pkg = f"""
    INSERT INTO software
    (os_id, package_name, version)
    VALUES
    ({os_id}, '{name}', '{version}');
    """

    subprocess.run([
        "docker", "exec", "-i",
        "postgres",
        "psql",
        "-U", "monitor",
        "-d", "monitoring",
        "-q",
        "-c",
        insert_pkg
    ])