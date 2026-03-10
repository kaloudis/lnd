package zpay32

const (
	// MetadataFlagHodlInvoice is a bit flag within the invoice metadata
	// byte that signals the invoice is a hodl invoice. When set, it
	// indicates that the receiver does not intend to settle the payment
	// immediately, and it may take some time to resolve.
	MetadataFlagHodlInvoice byte = 1 << 0
)

// EncodeInvoiceMetadata encodes invoice metadata flags into a single byte.
// The flags parameter is a bitmap where each bit represents a specific
// property of the invoice.
func EncodeInvoiceMetadata(flags byte) []byte {
	return []byte{flags}
}

// DecodeInvoiceMetadata returns the flags byte from the invoice metadata.
// If the metadata is empty, a zero value is returned.
func DecodeInvoiceMetadata(metadata []byte) byte {
	if len(metadata) == 0 {
		return 0
	}

	return metadata[0]
}

// IsHodlInvoiceMetadata returns true if the given invoice metadata contains
// the hodl invoice flag.
func IsHodlInvoiceMetadata(metadata []byte) bool {
	return DecodeInvoiceMetadata(metadata)&MetadataFlagHodlInvoice != 0
}
