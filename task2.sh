#!/bin/bash

HOST_UUID=$(cat /proc/sys/kernel/random/uuid)
HOSTNAME=$(hostname)
OS_NAME=$(uname -o)
KERNEL=$(uname -r)

OS_ID=$(docker exec -i postgres psql -U monitor -d monitoring -t -c "
INSERT INTO os_info
(host_uuid, hostname, os_name, kernel_version)
VALUES
('$HOST_UUID', '$HOSTNAME', '$OS_NAME', '$KERNEL')
RETURNING id;
" | tr -d ' ')

jq -c '.components[]' /home/arch/sbom/sbom.json | while read i
do
    NAME=$(echo $i | jq -r '.name')
    VERSION=$(echo $i | jq -r '.version')

    docker exec -i postgres psql -U monitor -d monitoring -c "
    INSERT INTO software
    (os_id, package_name, version)
    VALUES
    ($OS_ID, '$NAME', '$VERSION');
    " > /dev/null
done