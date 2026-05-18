import json
import uuid
import socket
import psycopg2
import platform

conn = psycopg2.connect(
    host="localhost",
    database="monitoring",
    user="monitor",
    password="monitorpass"
)

cur = conn.cursor()

with open("/root/task4/sbom.json") as f:
    data = json.load(f)

host_uuid = str(uuid.uuid4())

hostname = socket.gethostname()

os_name = platform.system()

kernel = platform.release()

cur.execute("""
INSERT INTO os_info
(host_uuid, hostname, os_name, kernel_version)
VALUES (%s,%s,%s,%s)
RETURNING id
""", (host_uuid, hostname, os_name, kernel))

os_id = cur.fetchone()[0]

for comp in data.get("components", []):

    name = comp.get("name")
    version = comp.get("version")

    cur.execute("""
    INSERT INTO software
    (os_id, package_name, version)
    VALUES (%s,%s,%s)
    """, (os_id, name, version))

conn.commit()

cur.close()
conn.close()