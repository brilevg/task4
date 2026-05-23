#!/bin/bash

HOST_UUID=$(cat /proc/sys/kernel/random/uuid)

OS_NAME=$(uname -o)

KERNEL=$(uname -r)

OS_ID=$(docker exec -i postgres psql -U monitor -d monitoring -t -c "
INSERT INTO os_info
(host_uuid, hostname, os_name, kernel_version)
VALUES
('$HOST_UUID', 'archlinux', '$OS_NAME', '$KERNEL')
RETURNING id;
" | tr -d ' ')

grep '"name"' /root/task4/sbom.json > /tmp/names.txt
grep '"version"' /root/task4/sbom.json > /tmp/versions.txt

paste /tmp/names.txt /tmp/versions.txt | while read line
do
    NAME=$(echo "$line" | cut -d '"' -f4)

    VERSION=$(echo "$line" | rev | cut -d '"' -f2 | rev)

    docker exec -i postgres psql -U monitor -d monitoring -c "
    INSERT INTO software
    (os_id, package_name, version)
    VALUES
    ($OS_ID, '$NAME', '$VERSION');
    " > /dev/null
done