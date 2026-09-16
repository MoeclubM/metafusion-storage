package objects

import "testing"

// 内容寻址键必须只由 sha256 决定：同一内容无论文件名怎么变都落到同一个键，
// 否则"秒传"会退化成重复存储。
func TestKeyForIsContentAddressed(t *testing.T) {
	s := &Store{}
	a := s.KeyFor("ab34cd", "track.flac")
	b := s.KeyFor("ab34cd", "track (remaster).flac")
	if a == b {
		t.Fatal("不同文件名不应产生同一个键")
	}
	if again := s.KeyFor("ab34cd", "track.flac"); again != a {
		t.Fatalf("同一输入键不稳定: %s != %s", again, a)
	}
	if want := "objects/ab/ab34cd/track.flac"; a != want {
		t.Fatalf("键格式不符: %s", a)
	}
}

// 文件名只作可读后缀：路径穿越与危险字符不能进入对象键。
func TestSanitizeNameStripsUnsafeCharacters(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd": "passwd",
		"a/b/c.flac":       "c.flac",
		"quo\"te.bin":      "quo_te.bin",
		"":                 "blob",
		"..":               "blob",
		"a/..":             "blob",
		"日本語.flac":         "___.flac",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Fatalf("sanitizeName(%q) = %q, 期望 %q", in, got, want)
		}
	}
}
