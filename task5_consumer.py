import json
import subprocess

from kafka import KafkaConsumer


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


consumer = KafkaConsumer(

    'sbom-data',
    'osv-data',

    bootstrap_servers='localhost:9092',

    value_deserializer=lambda m:
    json.loads(m.decode('utf-8'))
)


print("Kafka consumer started")


for message in consumer:

    topic = message.topic

    data = message.value

    #
    # =========================
    # SBOM
    # =========================
    #

    if topic == "sbom-data":

        print("Processing SBOM")

        host_uuid = data["host_uuid"]

        hostname = data["hostname"]

        os_name = data["os_name"]

        kernel = data["kernel_version"]

        components = data["components"]

        package_count = len(components)

        #
        # host exists
        #

        host_check = psql(f"""

        SELECT id
        FROM hosts
        WHERE host_uuid = '{host_uuid}';

        """)

        #
        # create host
        #

        if not host_check:

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

            host_id = psql(f"""

            SELECT id
            FROM hosts
            WHERE host_uuid = '{host_uuid}';

            """)

        else:
            host_id = host_check

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

        scan_id = psql("""

        SELECT MAX(id)
        FROM scans;

        """)

        #
        # insert packages
        #
        values = []
        for comp in components:

            name = comp.get("name")

            version = comp.get("version", "unknown")

            if not name:
                continue

            #
            # escape '
            #

            name = name.replace("'", "''")

            version = version.replace("'", "''")
            values.append(f"({scan_id}, '{name}', '{version}')")
            psql(f"""

            INSERT INTO software
            (
                scan_id,
                package_name,
                version
            )

            VALUES
            {",".join(values)};

            """)

        print("SBOM saved")

    #
    # =========================
    # OSV
    # =========================
    #

    elif topic == "osv-data":

        print("Processing OSV")

        results = data.get("results", [])

        scan_id = psql("""

        SELECT MAX(id)
        FROM scans;

        """)

        for result in results:

            packages = result.get("packages", [])

            for pkg in packages:

                package_name = pkg.get(
                    "package",
                    {}
                ).get(
                    "name",
                    "unknown"
                )

                package_version = pkg.get(
                    "package",
                    {}
                ).get(
                    "version",
                    "unknown"
                )

                vulns = pkg.get(
                    "vulnerability",
                    []
                )

                for vuln in vulns:

                    vuln_id = vuln.get(
                        "id",
                        "unknown"
                    )

                    summary = vuln.get(
                        "summary",
                        ""
                    )

                    severity = "UNKNOWN"

                    severity_list = vuln.get(
                        "severity",
                        []
                    )

                    if severity_list:

                        severity = severity_list[0].get(
                            "score",
                            "UNKNOWN"
                        )

                    #
                    # escape '
                    #

                    vuln_id = vuln_id.replace("'", "''")

                    summary = summary.replace("'", "''")

                    package_name = package_name.replace("'", "''")

                    package_version = package_version.replace("'", "''")

                    #
                    # vulnerability exists
                    #

                    vuln_exists = psql(f"""

                    SELECT id
                    FROM vulnerability
                    WHERE vuln_id = '{vuln_id}';

                    """)

                    #
                    # create vulnerability
                    #

                    if not vuln_exists:

                        psql(f"""

                        INSERT INTO vulnerability
                        (
                            vuln_id,
                            summary,
                            severity
                        )

                        VALUES
                        (
                            '{vuln_id}',
                            '{summary}',
                            '{severity}'
                        );

                        """)

                        vuln_exists = psql(f"""

                        SELECT id
                        FROM vulnerability
                        WHERE vuln_id = '{vuln_id}';

                        """)

                    #
                    # insert detection
                    #

                    psql(f"""

                    INSERT INTO vulnerability_scans
                    (
                        scan_id,
                        vulnerability_id,
                        package_name,
                        package_version
                    )

                    VALUES
                    (
                        {scan_id},
                        {vuln_exists},
                        '{package_name}',
                        '{package_version}'
                    );

                    """)

        print("OSV saved")