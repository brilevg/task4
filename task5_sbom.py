import json
import platform
import uuid
import socket

from kafka import KafkaProducer


SBOM_PATH = "/root/task4/sbom/sbom.json"

HOST_UUID = str(uuid.uuid5(
    uuid.NAMESPACE_DNS,
    socket.gethostname()
))

HOSTNAME = socket.gethostname()

OS_NAME = platform.system()

KERNEL = platform.release()


producer = KafkaProducer(
    bootstrap_servers='localhost:9092',

    value_serializer=lambda v:
    json.dumps(v).encode('utf-8')
)


with open(SBOM_PATH, "r") as f:

    data = json.load(f)


components = data.get("components", [])


message = {

    "host_uuid": HOST_UUID,

    "hostname": HOSTNAME,

    "os_name": OS_NAME,

    "kernel_version": KERNEL,

    "package_count": len(components),

    "components": components
}


producer.send(
    "sbom-data",
    message
)

producer.flush()

print("SBOM sent to Kafka")