package pipeline

import "io"

var OnProgress func(bytesRead int64)

type ProgressReader struct {
	r          io.Reader
	OnProgress func(int64)
}

func (pr *ProgressReader) Read(p []byte) (n int, err error) {
	n, err = pr.r.Read(p)
	if n > 0 && pr.OnProgress != nil {
		pr.OnProgress(int64(n))
	}
	return n, err
}
