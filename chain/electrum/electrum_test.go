package electrum

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestScriptHashToElectrumScriptHash tests the conversion of a pkScript to the
// Electrum protocol's script hash format.
func TestScriptHashToElectrumScriptHash(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		pkScript string // Hex encoded pkScript
		expected string // Expected Electrum script hash
	}{
		{
			// Example from ElectrumX documentation for address
			// 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
			// pkScript: OP_DUP OP_HASH160 <20_byte_hash> OP_EQUALVERIFY OP_CHECKSIG
			// pkScript hex: 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
			name:     "P2PKH",
			pkScript: "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
			expected: "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161",
		},
		{
			// Example for P2SH address 34M7XNrn1kX4ZNC5UD2AbfR7gQ1N1trL4b
			// pkScript: OP_HASH160 <20_byte_hash> OP_EQUAL
			// pkScript hex: a9141c915b19d1ff116114a98460177148909c41a86e87
			name:     "P2SH",
			pkScript: "a9141c915b19d1ff116114a98460177148909c41a86e87",
			expected: "a1e6705811b1456d51787d1a4a107e0d61041e3a939a44632961608061f5786c",
		},
		{
			// Example for P2WPKH address bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
			// pkScript: OP_0 <20_byte_hash>
			// pkScript hex: 0014751e76e8199196d454941c45d1b3a323f1433bd6
			name:     "P2WPKH",
			pkScript: "0014751e76e8199196d454941c45d1b3a323f1433bd6",
			expected: "7f99b018b41317d585a17c60f9a95476e84e570e174e1ede5ad995fbf986ce4c",
		},
		{
			// Example for P2WSH address bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
			// pkScript: OP_0 <32_byte_hash>
			// pkScript hex: 00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262
			name:     "P2WSH",
			pkScript: "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
			expected: "9941cacfa635e687c9048a1495f73e86415cec29031ace3ff45302a83998a118",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pkScriptBytes, err := hex.DecodeString(tc.pkScript)
			if err != nil {
				t.Fatalf("Failed to decode pkScript hex: %v", err)
			}

			actual := scriptHashToElectrumScriptHash(pkScriptBytes)

			if actual != tc.expected {
				t.Errorf("Expected script hash %s, got %s", tc.expected, actual)
			}

			// Test reverse (decode expected, encode again)
			expectedBytes, err := hex.DecodeString(tc.expected)
			if err != nil {
				t.Fatalf("Failed to decode expected hex: %v", err)
			}
			// Reverse bytes before comparing with sha256 output
			for i, j := 0, len(expectedBytes)-1; i < j; i, j = i+1, j-1 {
				expectedBytes[i], expectedBytes[j] = expectedBytes[j], expectedBytes[i]
			}

			actualHashBytes := sha256.Sum256(pkScriptBytes)
			if !bytes.Equal(actualHashBytes[:], expectedBytes) {
				t.Errorf("Reverse check failed: Expected hash %x, got %x",
					expectedBytes, actualHashBytes[:])
			}
		})
	}
}
