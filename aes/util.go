package aes

import (
	"errors"

	"github.com/usthooz/gutil"
)

var (
	random = gutil.NewRandom(gutil.UpperWordsAndNumber)
)

// GetRandomAesKey 获取AES加密key
func GetRandomAesKey(len int) string {
	return random.RandomString(len)
}

// padData 分组
func padData(d []byte, bs int) []byte {
	padedSize := ((len(d) / bs) + 1) * bs
	pad := padedSize - len(d)
	for i := len(d); i < padedSize; i++ {
		d = append(d, byte(pad))
	}
	return d
}

// removePad
func removePad(r []byte) ([]byte, error) {
	l := len(r)
	if l == 0 {
		return []byte{}, errors.New("input []byte is empty")
	}
	last := int(r[l-1])
	pad := r[l-last : l]
	isPad := true
	for _, v := range pad {
		if int(v) != last {
			isPad = false
			break
		}
	}
	if !isPad {
		return r, errors.New("remove pad error")
	}
	return r[:l-last], nil
}
