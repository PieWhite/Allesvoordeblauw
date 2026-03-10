package main

import (
	"fmt"
	"io"
	"os"
)

func setupOutput(outputFile string) (io.Writer, func(), error) {

	var writers []io.Writer
	consoleWriter := os.Stdout
	writers = append(writers, consoleWriter)

	if outputFile == "" {
		return io.MultiWriter(writers...), func() {}, nil
	}

	fileWriter, err := os.Create(outputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("Something went wrong while creating output file: %v", err)
	}

	writers = append(writers, fileWriter)

	cleanup := func() {
		fileWriter.Close()
	}

	return io.MultiWriter(writers...), cleanup, nil

}
