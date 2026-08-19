package postgres

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
