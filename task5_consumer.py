import json

import psycopg2

from kafka import KafkaConsumer


#
# PostgreSQL connection
#

conn = psycopg2.connect(
    host="localhost",
    database="monitoring",
    user="monitor",
    password="monitorpass"
)

cur = conn.cursor()


#
# Kafka consumer
#

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

        print("Processing SBOM data")

        host_uuid = data["host_uuid"]

        hostname = data["hostname"]

        os_name = data["os_name"]

        kernel = data["kernel_version"]

        components = data["components"]

        package_count = len(components)

        #
        # host exists
        #

        cur.execute("""

        SELECT id
        FROM hosts
        WHERE host_uuid = %s;

        """, (host_uuid,))

        host = cur.fetchone()

        #
        # create host
        #

        if not host:

            cur.execute("""

            INSERT INTO hosts
            (
                host_uuid,
                hostname,
                os_name,
                kernel_version
            )

            VALUES
            (%s, %s, %s, %s)

            RETURNING id;

            """, (

                host_uuid,
                hostname,
                os_name,
                kernel
            ))

            host_id = cur.fetchone()[0]

            conn.commit()

        else:
            host_id = host[0]

        #
        # create scan
        #

        cur.execute("""

        INSERT INTO scans
        (
            host_id,
            package_count
        )

        VALUES
        (%s, %s)

        RETURNING id;

        """, (

            host_id,
            package_count
        ))

        scan_id = cur.fetchone()[0]

        conn.commit()

        #
        # insert packages
        #

        for comp in components:

            name = comp.get("name")

            version = comp.get("version", "unknown")

            if not name:
                continue

            cur.execute("""

            INSERT INTO software
            (
                scan_id,
                package_name,
                version
            )

            VALUES
            (%s, %s, %s);

            """, (

                scan_id,
                name,
                version
            ))

        conn.commit()

        print("SBOM saved to PostgreSQL")

    #
    # =========================
    # OSV
    # =========================
    #

    elif topic == "osv-data":

        print("Processing OSV data")

        results = data.get("results", [])

        #
        # latest scan
        #

        cur.execute("""

        SELECT MAX(id)
        FROM scans;

        """)

        scan_id = cur.fetchone()[0]

        if not scan_id:

            print("No scans found")

            continue

        #
        # parse osv
        #

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
                    # vulnerability exists
                    #

                    cur.execute("""

                    SELECT id
                    FROM vulnerability
                    WHERE vuln_id = %s;

                    """, (vuln_id,))

                    vuln_exists = cur.fetchone()

                    #
                    # create vulnerability
                    #

                    if not vuln_exists:

                        cur.execute("""

                        INSERT INTO vulnerability
                        (
                            vuln_id,
                            summary,
                            severity
                        )

                        VALUES
                        (%s, %s, %s)

                        RETURNING id;

                        """, (

                            vuln_id,
                            summary,
                            severity
                        ))

                        vulnerability_id = cur.fetchone()[0]

                        conn.commit()

                    else:
                        vulnerability_id = vuln_exists[0]

                    #
                    # insert detection
                    #

                    cur.execute("""

                    INSERT INTO vulnerability_scans
                    (
                        scan_id,
                        vulnerability_id,
                        package_name,
                        package_version
                    )

                    VALUES
                    (%s, %s, %s, %s);

                    """, (

                        scan_id,
                        vulnerability_id,
                        package_name,
                        package_version
                    ))

        conn.commit()

        print("OSV saved to PostgreSQL")