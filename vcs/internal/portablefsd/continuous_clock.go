package portablefsd

import "errors"

func v3TimespecNanos(sec, nsec int64) (uint64, error) {
	if sec < 0 || nsec < 0 || nsec >= 1e9 || uint64(sec) > (^uint64(0)-uint64(nsec))/1e9 {
		return 0, errors.New("portablefsd: continuous clock timespec is out of range")
	}
	return uint64(sec)*1e9 + uint64(nsec), nil
}
