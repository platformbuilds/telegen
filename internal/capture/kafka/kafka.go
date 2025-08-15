package kafka

// Very lightweight recognizer for Kafka request API key bytes (first two bytes).
func MaybeKafka(prefix []byte) bool {
	if len(prefix) < 2 {
		return false
	}
	return true
}
