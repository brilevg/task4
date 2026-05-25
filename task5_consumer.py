import json
import subprocess

from kafka import KafkaConsumer


def psql(query: str):

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


#
# SBOM consumer
#

sbom_consumer = KafkaConsumer(
    "sbom-data",

    bootstrap_servers='localhost:9092',

    value_deserializer=lambda m:
    json.loads(m.decode('utf-8'))
)


print("SBOM consumer started")


for message in sbom_consumer:

    data = message.value

    host_uuid = data["host_uuid"]

    hostname = data["hostname"]

    os_name = data["os_name"]

    kernel = data["kernel_version"]

    package_count = data["package_count"]

    components = data["components"]


    #
    # host exists
    #

    result = subprocess.check_output([

        "docker", "exec", "-i",
        "postgres",

        "psql",

        "-U", "monitor",

        "-d", "monitoring",

        "-t",

        "-A",

        "-c",

        f"""
        SELECT id
        FROM hosts
        WHERE host_uuid = '{host_uuid}';
        """
    ])


    host_id = result.decode().strip()


    if not host_id:

        psql(f"""
        INSERT INTO hosts
        (
            host_uuid,
            hostname,
            os_name,
            kernel_version
        )
        VALUES
        (
            '{host_uuid}',
            '{hostname}',
            '{os_name}',
            '{kernel}'
        );
        """)

        result = subprocess.check_output([

            "docker", "exec", "-i",
            "postgres",

            "psql",

            "-U", "monitor",

            "-d", "monitoring",

            "-t",

            "-A",

            "-c",

            f"""
            SELECT id
            FROM hosts
            WHERE host_uuid = '{host_uuid}';
            """
        ])

        host_id = result.decode().strip()


    #
    # create scan
    #

    psql(f"""
    INSERT INTO scans
    (
        host_id,
        package_count
    )
    VALUES
    (
        {host_id},
        {package_count}
    );
    """)


    result = subprocess.check_output([

        "docker", "exec", "-i",
        "postgres",

        "psql",

        "-U", "monitor",

        "-d", "monitoring",

        "-t",

        "-A",

        "-c",

        "SELECT MAX(id) FROM scans;"
    ])


    scan_id = result.decode().strip()


    #
    # packages
    #

    for comp in components:

        name = comp.get("name")

        version = comp.get("version", "unknown")


        if not name:
            continue


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


    print("SBOM saved to PostgreSQL")