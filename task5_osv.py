import json

from kafka import KafkaProducer


producer = KafkaProducer(
    bootstrap_servers='localhost:9092',

    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

with open('/root/task4/osv-result.json', 'r') as f:

    data = json.load(f)

producer.send(
    'vulnerabilities-data',
    data
)

producer.flush()

print('OSV data sent to Kafka')