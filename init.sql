CREATE TABLE os_info (
    id SERIAL PRIMARY KEY,
    host_uuid TEXT,
    hostname TEXT,
    os_name TEXT,
    kernel_version TEXT,
    collected_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE software (
    id SERIAL PRIMARY KEY,
    os_id INTEGER REFERENCES os_info(id),
    package_name TEXT,
    version TEXT
);