package kafka

// Very lightweight recognizer for Kafka request API key bytes (first two bytes).
func MaybeKafka(prefix []byte) bool {
    if len(prefix) < 2 { return false }
    // Request header starts with ApiKey (int16). We don't decode fully here.
    return true
}
