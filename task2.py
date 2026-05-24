import json
import subprocess
import platform
import uuid
import socket

SBOM_PATH = "/root/task4/sbom/sbom.json"

HOST_UUID = str(uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname()))

HOSTNAME = socket.gethostname()

OS_NAME = platform.system()

KERNEL = platform.release()


def psql(query: str):

    result = subprocess.check_output([
        "docker", "exec", "-i",
        "postgres",
        "psql",
        "-U", "monitor",
        "-d", "monitoring",
        "-t",
        "-A",
        "-c",
        query
    ])

    return result.decode().strip()


with open(SBOM_PATH, "r") as f:
    data = json.load(f)

components = data.get("components", [])

PACKAGE_COUNT = len(components)

#
# Проверяем существование host
#

host_check = psql(f"""
SELECT id
FROM hosts
WHERE host_uuid = '{HOST_UUID}';
""")

#
# Если host отсутствует
#

if not host_check:

    psql(f"""
    INSERT INTO hosts
    (host_uuid, hostname, os_name, kernel_version)
    VALUES
    (
        '{HOST_UUID}',
        '{HOSTNAME}',
        '{OS_NAME}',
        '{KERNEL}'
    );
    """)

    host_id = psql(f"""
    SELECT id
    FROM hosts
    WHERE host_uuid = '{HOST_UUID}';
    """)

else:
    host_id = host_check

#
# Создаём scan
#

psql(f"""
INSERT INTO scans
(host_id, package_count)
VALUES
(
    {host_id},
    {PACKAGE_COUNT}
);
""")

scan_id = psql("""
SELECT MAX(id)
FROM scans;
""")

#
# Добавляем packages
#

for comp in components:

    name = comp.get("name")

    version = comp.get("version")

    if not name:
        continue

    if not version:
        version = "unknown"

    #
    # Экранирование '
    #

    name = name.replace("'", "''")

    version = version.replace("'", "''")

    psql(f"""
    INSERT INTO software
    (
        scan_id,
        package_name,
        version
    )
    VALUES
    (
        {scan_id},
        '{name}',
        '{version}'
    );
    """)

print("SBOM import completed")