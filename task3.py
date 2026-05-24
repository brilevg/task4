import json
import subprocess

OSV_PATH = "/root/task4/osv.json"


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


with open(OSV_PATH, "r") as f:
    data = json.load(f)

results = data.get("results", [])


scan_id = psql("""
SELECT MAX(id)
FROM scans;
""")

for result in results:

    packages = result.get("packages", [])

    for pkg in packages:

        package_name = pkg.get("package", {}).get("name", "unknown")

        package_version = pkg.get("package", {}).get("version", "unknown")

        vulns = pkg.get("vulnerabilities", [])

        for vuln in vulns:

            vuln_id = vuln.get("id", "unknown")

            summary = vuln.get("summary", "")

            severity = "UNKNOWN"

            severity_list = vuln.get("severity", [])

            if severity_list:

                severity = severity_list[0].get("score", "UNKNOWN")


            vuln_id = vuln_id.replace("'", "''")

            summary = summary.replace("'", "''")

            package_name = package_name.replace("'", "''")

            package_version = package_version.replace("'", "''")



            vuln_exists = psql(f"""
            SELECT id
            FROM vulnerabilities
            WHERE vuln_id = '{vuln_id}';
            """)

            if not vuln_exists:

                psql(f"""
                INSERT INTO vulnerabilities
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
                FROM vulnerabilities
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

print("OSV import completed")