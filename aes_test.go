package main

import "testing"

const decStr = "test_string"

const encString = `eyJpdiI6InkyYjZnV1pPOHNVN3JYTGMwUklXb0E9PSIsIm1hYyI6IjkwNjkzZWFiNzk1OTVmMThmMzViYzJkMjBkZGE0MjZkMTcwZWUzOTY0ZDJjOTE3NTYwMDFiZjdjYjY2MTJmM2QiLCJ2YWx1ZSI6Ik1GVGxQTmJVengzekF5U0hkcVRtaFE9PSJ9`

const appKey = "ffew3ds7um86jcvfructka43gnpfjtuf"

func TestDecrypt(t *testing.T) {
	type args struct {
		value string
		key   string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"1st", args{value: encString, key: appKey}, decStr, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt(tt.args.value, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
