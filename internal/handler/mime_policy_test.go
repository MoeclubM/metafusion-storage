package handler

import "testing"

// 白名单的判定边界：能当"可执行文档"渲染的类型一个都不能内联（审计 S-3 的三个必须项），
// 带参数与大小写都要按基础类型判定，未知类型默认不内联。
func TestInlineAllowedBoundaries(t *testing.T) {
	cases := []struct {
		mime string
		want bool
	}{
		// 必须强制附件：会被浏览器当文档执行
		{"text/html", false},
		{"text/html; charset=utf-8", false},
		{"TEXT/HTML", false},
		{"image/svg+xml", false},
		{"Image/SVG+XML", false},
		{"application/xhtml+xml", false},
		{"text/xml", false},
		{"application/xml", false},
		{"text/javascript", false},
		{"application/javascript", false},
		// 白名单内的展示类型
		{"image/png", true},
		{"image/jpeg", true},
		{"image/webp", true},
		{"Image/PNG", true},
		{"audio/mpeg", true},
		{"video/mp4", true},
		{"text/plain; charset=utf-8", true},
		{"application/pdf", true},
		// 其余一律附件
		{"application/octet-stream", false},
		{"application/zip", false},
		{"text/csv", false},
		{"", false},
		{"not a mime", false},
	}
	for _, tc := range cases {
		if got := inlineAllowed(tc.mime); got != tc.want {
			t.Errorf("inlineAllowed(%q) = %v, want %v", tc.mime, got, tc.want)
		}
	}
}
