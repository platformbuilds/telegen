# Telegen v3+ (enriched spans + unit tests)

What's new:
- **DB & Kafka spans enriched** with `peer.service`, `db.namespace`, and `messaging.destination` (demo generator).
- **Unit tests** covering parsers (Cassandra, PostgreSQL, Kafka), HTTP classifier, and ring queue behavior.

Run tests:
```bash
go test ./...
```
