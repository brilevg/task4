import json
import subprocess

from kafka import KafkaConsumer


def psql(query):

    subprocess.run([
        "docker", "exec", "-i",
        "postgres",
        "psql",
        "-U", "monitor",
        "-d", "monitoring",
        "-q",
        "-c",
        query
    ])

sbom_consumer = KafkaConsumer(
    'sbom-data',

    bootstrap_servers='localhost:9092',

    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

osv_consumer = KafkaConsumer(
    'vulnerabilities-data',

    bootstrap_servers='localhost:9092',

    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

print("Kafka consumer started")

for message in sbom_consumer:

    data = message.value

    components = data.get("components", [])

    psql("""
    INSERT INTO scans (host_id, package_count)
    VALUES (1, %d);
    """ % len(components))

    for comp in components[:10]:

        name = comp.get("name", "unknown")

        version = comp.get("version", "unknown")

        name = name.replace("'", "''")

        version = version.replace("'", "''")

        psql(f"""
        INSERT INTO software
        (scan_id, package_name, version)
        VALUES
        (
            (SELECT MAX(id) FROM scans),
            '{name}',
            '{version}'
        );
        """)

    break