CREATE TABLE hosts (
    id SERIAL PRIMARY KEY,

    host_uuid TEXT UNIQUE,

    hostname TEXT,

    os_name TEXT,

    kernel_version TEXT
);

CREATE TABLE scans (
    id SERIAL PRIMARY KEY,

    host_id INTEGER REFERENCES hosts(id),

    collected_at TIMESTAMP DEFAULT NOW(),

    package_count INTEGER
);

CREATE TABLE software (
    id SERIAL PRIMARY KEY,

    scan_id INTEGER REFERENCES scans(id),

    package_name TEXT,

    version TEXT
);

CREATE TABLE vulnerability (
    id SERIAL PRIMARY KEY,

    vuln_id TEXT,

    summary TEXT,

    severity TEXT
);

CREATE TABLE vulnerability_scans (
    id SERIAL PRIMARY KEY,

    scan_id INTEGER REFERENCES scans(id),

    vulnerability_id INTEGER REFERENCES vulnerability(id),

    package_name TEXT,

    package_version TEXT,

    found_at TIMESTAMP DEFAULT NOW()
);