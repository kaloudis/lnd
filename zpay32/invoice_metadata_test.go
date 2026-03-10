package zpay32

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEncodeDecodeInvoiceMetadata tests the round-trip encoding and decoding of
// invoice metadata with various flag combinations.
func TestEncodeDecodeInvoiceMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		flags uint64
	}{
		{
			name:  "no flags",
			flags: 0,
		},
		{
			name:  "hodl invoice flag",
			flags: MetadataFlagHodlInvoice,
		},
		{
			name:  "multiple flags",
			flags: MetadataFlagHodlInvoice | (1 << 1),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := EncodeInvoiceMetadata(tc.flags)
			require.NoError(t, err)
			require.NotEmpty(t, encoded)

			decoded, err := DecodeInvoiceMetadata(encoded)
			require.NoError(t, err)
			require.Equal(t, tc.flags, decoded)
		})
	}
}

// TestDecodeEmptyMetadata tests that decoding empty or nil metadata returns
// zero flags without error.
func TestDecodeEmptyMetadata(t *testing.T) {
	t.Parallel()

	flags, err := DecodeInvoiceMetadata(nil)
	require.NoError(t, err)
	require.Equal(t, uint64(0), flags)

	flags, err = DecodeInvoiceMetadata([]byte{})
	require.NoError(t, err)
	require.Equal(t, uint64(0), flags)
}

// TestIsHodlInvoiceMetadata tests the convenience function for checking the
// hodl invoice flag in metadata.
func TestIsHodlInvoiceMetadata(t *testing.T) {
	t.Parallel()

	// Empty metadata should not be hodl.
	require.False(t, IsHodlInvoiceMetadata(nil))
	require.False(t, IsHodlInvoiceMetadata([]byte{}))

	// Metadata with hodl flag set.
	hodlMeta, err := EncodeInvoiceMetadata(MetadataFlagHodlInvoice)
	require.NoError(t, err)
	require.True(t, IsHodlInvoiceMetadata(hodlMeta))

	// Metadata with only other flags (not hodl).
	otherMeta, err := EncodeInvoiceMetadata(1 << 5)
	require.NoError(t, err)
	require.False(t, IsHodlInvoiceMetadata(otherMeta))

	// Metadata with hodl flag and other flags.
	combinedMeta, err := EncodeInvoiceMetadata(
		MetadataFlagHodlInvoice | (1 << 5),
	)
	require.NoError(t, err)
	require.True(t, IsHodlInvoiceMetadata(combinedMeta))
}
