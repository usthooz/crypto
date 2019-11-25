package aes

import (
	"testing"

	"github.com/usthooz/gutil"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func TestAes(t *testing.T) {
	user := &User{
		Username: "usthooz",
		Password: "usthooz",
	}
	// 将结构体转换为[]byte
	userb, err := gutil.InterfaceToBytes(user)
	if err != nil {
		t.Errorf("InterfaceToBytes err-> %v", err)
		return
	}
	xaes := &OozAes{
		Key:        GetRandomAesKey(32),
		DecodeData: userb,
	}
	t.Logf("key-> %s", xaes.Key)

	// 加密
	endata := xaes.Encrypt()
	t.Logf("Encrypt Data-> %s", endata)

	// 设置需要解密的数据
	xaes.EncryptData = endata

	// 解密
	dedata, err := xaes.Decode()
	if err != nil {
		t.Errorf("Decode err-> %v", err)
		return
	}
	t.Logf("Decode Data-> %s", string(dedata))

	// 转换为map
	dem, err := gutil.BytesToMapInterface(dedata)
	if err != nil {
		t.Errorf("BytesToMapInterface err-> %v", err)
		return
	}

	// 解密后从map中取出数据
	if name, ok := dem["username"]; ok {
		t.Logf("username-> %s", name)
	}
	if pwd, ok := dem["password"]; ok {
		t.Logf("password-> %s", pwd)
	}
}

func TestAes1(t *testing.T) {
	// 加密
	endata := Encrypt("5FXBBDDC6DVPCU84OE7FUMDT6SB47QRF", []byte("123456"))
	t.Logf("Encrypt Data1-> %s", endata)

	// 解密
	dedata, err := Decode("5FXBBDDC6DVPCU84OE7FUMDT6SB47QRF", []byte("891a0d6ae23e2ec7cdea93e98e03f012"))
	if err != nil {
		t.Errorf("Decode1 err-> %v", err)
		return
	}
	t.Logf("Decode Data1-> %v", string(dedata))
}
