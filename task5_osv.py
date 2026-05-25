import json

from kafka import KafkaProducer


OSV_PATH = "/root/task4/osv.json"


producer = KafkaProducer(
    bootstrap_servers='localhost:9092',

    value_serializer=lambda v:
    json.dumps(v).encode('utf-8')
)


with open(OSV_PATH, "r") as f:

    data = json.load(f)


producer.send(
    "osv-data",
    data
)

producer.flush()

print("OSV data sent to Kafka")