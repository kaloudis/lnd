package zpay32

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// MetadataFeatureFlagsType is the TLV type used to encode feature
	// flags in the invoice metadata. The type prefix avoids collisions
	// with other potential uses of the metadata field.
	MetadataFeatureFlagsType tlv.Type = 0

	// MetadataFlagHodlInvoice is a bit flag within the metadata feature
	// flags that signals the invoice is a hodl invoice. When set, it
	// indicates that the receiver does not intend to settle the payment
	// immediately, and it may take some time to resolve.
	MetadataFlagHodlInvoice uint8 = 1 << 0
)

// EncodeInvoiceMetadata encodes invoice metadata flags into a TLV-encoded byte
// slice. The flags parameter is a bitmap where each bit represents a specific
// property of the invoice. The TLV encoding uses 3 bytes total: 1 byte type,
// 1 byte length, 1 byte value.
func EncodeInvoiceMetadata(flags uint8) ([]byte, error) {
	flagsVal := flags

	record := tlv.MakePrimitiveRecord(
		MetadataFeatureFlagsType, &flagsVal,
	)

	stream, err := tlv.NewStream(record)
	if err != nil {
		return nil, fmt.Errorf("unable to create metadata stream: %w",
			err)
	}

	var buf bytes.Buffer
	if err := stream.Encode(&buf); err != nil {
		return nil, fmt.Errorf("unable to encode metadata: %w", err)
	}

	return buf.Bytes(), nil
}

// DecodeInvoiceMetadata decodes a TLV-encoded invoice metadata byte slice and
// returns the feature flags bitmap. If the metadata is empty or does not
// contain the feature flags TLV type, a zero value is returned.
func DecodeInvoiceMetadata(metadata []byte) (uint8, error) {
	if len(metadata) == 0 {
		return 0, nil
	}

	var flags uint8
	record := tlv.MakePrimitiveRecord(
		MetadataFeatureFlagsType, &flags,
	)

	stream, err := tlv.NewStream(record)
	if err != nil {
		return 0, fmt.Errorf("unable to create metadata stream: %w",
			err)
	}

	r := bytes.NewReader(metadata)
	parsedTypes, err := stream.DecodeWithParsedTypes(r)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return 0, fmt.Errorf("unable to decode metadata: %w", err)
	}

	// Check that the feature flags type was actually parsed.
	if _, ok := parsedTypes[MetadataFeatureFlagsType]; !ok {
		return 0, nil
	}

	return flags, nil
}

// IsHodlInvoiceMetadata returns true if the given TLV-encoded invoice metadata
// contains the hodl invoice flag.
func IsHodlInvoiceMetadata(metadata []byte) bool {
	flags, err := DecodeInvoiceMetadata(metadata)
	if err != nil {
		return false
	}

	return flags&MetadataFlagHodlInvoice != 0
}
