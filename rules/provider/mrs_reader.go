package provider

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

var MrsMagicBytes = [4]byte{'M', 'R', 'S', 1} // MRSv1

func rulesMrsParse(buf []byte, strategy ruleStrategy) (ruleStrategy, error) {
	if _strategy, ok := strategy.(mrsRuleStrategy); ok {
		reader, err := zstd.NewReader(bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
		defer reader.Close()

		// header
		var header [4]byte
		_, err = io.ReadFull(reader, header[:])
		if err != nil {
			return nil, err
		}
		if header != MrsMagicBytes {
			return nil, fmt.Errorf("invalid MrsMagic bytes")
		}

		// behavior
		var _behavior [1]byte
		_, err = io.ReadFull(reader, _behavior[:])
		if err != nil {
			return nil, err
		}
		if _behavior[0] != strategy.Behavior().Byte() {
			return nil, fmt.Errorf("invalid behavior")
		}

		// count
		var count int64
		err = binary.Read(reader, binary.BigEndian, &count)
		if err != nil {
			return nil, err
		}

		// No budget check here on purpose. The rule-count cap exists to prevent
		// the trie construction spike (NewDomainSet materialising and sorting
		// every domain), and the MRS path does none of that: FromMrs reads a
		// pre-built succinct bitmap into three slices. Measured on BanAD
		// (187,945 rules): ~190 MB via the trie, 18 MB via MRS. Capping here
		// would reject exactly the artifact that makes big lists affordable.

		// extra (reserved for future using)
		var length int64
		err = binary.Read(reader, binary.BigEndian, &length)
		if err != nil {
			return nil, err
		}
		if length < 0 {
			return nil, errors.New("length is invalid")
		}
		if length > 0 {
			extra := make([]byte, length)
			_, err = io.ReadFull(reader, extra)
			if err != nil {
				return nil, err
			}
		}

		err = _strategy.FromMrs(reader, int(count))
		return strategy, err
	} else {
		return nil, ErrInvalidFormat
	}
}
