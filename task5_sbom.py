import json

from kafka import KafkaProducer


producer = KafkaProducer(
    bootstrap_servers='localhost:9092',

    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

with open('/root/task4/sbom/sbom.json', 'r') as f:

    data = json.load(f)

producer.send(
    'sbom-data',
    data
)

producer.flush()

print('SBOM sent to Kafka')