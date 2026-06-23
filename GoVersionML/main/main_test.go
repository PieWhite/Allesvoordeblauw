/*
Package main_test contains the unit tests for verifying CLI flag processing,
error conditions, and end-to-end execution of the entry point run function.
*/
package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRun_Errors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "no arguments",
			args: []string{},
		},
		{
			name: "invalid flag",
			args: []string{"--invalid-flag-that-does-not-exist"},
		},
		{
			name: "invalid CPU profile path",
			args: []string{"-cpuprofile", "nonexistent_dir/cpu.prof", "dummy_input.json"},
		},
		{
			name: "nonexistent input file",
			args: []string{"nonexistent_input.json"},
		},
		{
			name: "invalid output file path",
			args: []string{"-o", "nonexistent_dir/output.txt", "dummy_input.json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.args)
			if err == nil {
				t.Error("expected error but got nil")
			}
		})
	}
}

func TestRun_Help(t *testing.T) {
	err := run([]string{"-h"})
	if err != flag.ErrHelp {
		t.Errorf("expected flag.ErrHelp, got %v", err)
	}
}

func TestMain_Exit1_On_Error(t *testing.T) {
	if os.Getenv("TEST_MAIN_CRASHER") == "1" {
		os.Args = []string{"goversionML.exe", "--invalid-flag"}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Exit1_On_Error")
	cmd.Env = append(os.Environ(), "TEST_MAIN_CRASHER=1")
	err := cmd.Run()

	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestMain_Exit0_On_Help(t *testing.T) {
	if os.Getenv("TEST_MAIN_CRASHER") == "1" {
		os.Args = []string{"goversionML.exe", "-h"}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Exit0_On_Help")
	cmd.Env = append(os.Environ(), "TEST_MAIN_CRASHER=1")
	err := cmd.Run()

	if err != nil {
		t.Fatalf("process ran with err %v, want exit status 0", err)
	}
}

func TestRun_Success(t *testing.T) {
	modelPath := filepath.Join("..", "Xgboost", "botnet_xgboost.json")
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		t.Skipf("Model file %s not found, skipping success test", modelPath)
	}

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ndjson")
	validJSON := `{"first":"2026-03-17T12:00:00.000","last":"2026-03-17T12:00:01.000","in_packets":10,"in_bytes":100,"proto":6,"tcp_flags":"S","src_port":1234,"dst_port":80,"src4_addr":"192.168.1.1","dst4_addr":"10.0.0.1"}` + "\n"
	if err := os.WriteFile(testFile, []byte(validJSON), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	cpuProf := filepath.Join(tmpDir, "cpu.prof")
	memProf := filepath.Join(tmpDir, "mem.prof")
	outTxt := filepath.Join(tmpDir, "out.txt")

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	null, err := os.Open(os.DevNull)
	if err == nil {
		os.Stdout = null
		os.Stderr = null
		defer func() {
			os.Stdout = oldStdout
			os.Stderr = oldStderr
			null.Close()
		}()
	}

	args := []string{
		"-cpuprofile", cpuProf,
		"-memprofile", memProf,
		"-o", outTxt,
		testFile,
	}

	err = run(args)
	if err != nil {
		t.Errorf("expected successful run, got error: %v", err)
	}

	if _, err := os.Stat(cpuProf); os.IsNotExist(err) {
		t.Error("CPU profile was not created")
	}
	if _, err := os.Stat(memProf); os.IsNotExist(err) {
		t.Error("Memory profile was not created")
	}
	if _, err := os.Stat(outTxt); os.IsNotExist(err) {
		t.Error("Output text file was not created")
	}
}

func TestRun_InvalidMemProfile(t *testing.T) {
	modelPath := filepath.Join("..", "Xgboost", "botnet_xgboost.json")
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		t.Skipf("Model file %s not found, skipping memprofile error test", modelPath)
	}

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ndjson")
	validJSON := `{"first":"2026-03-17T12:00:00.000","last":"2026-03-17T12:00:01.000","in_packets":10,"in_bytes":100,"proto":6,"tcp_flags":"S","src_port":1234,"dst_port":80,"src4_addr":"192.168.1.1","dst4_addr":"10.0.0.1"}` + "\n"
	if err := os.WriteFile(testFile, []byte(validJSON), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	badMemProf := filepath.Join(tmpDir, "does_not_exist", "mem.prof")
	args := []string{
		"-memprofile", badMemProf,
		testFile,
	}

	err := run(args)
	if err == nil {
		t.Error("expected error for invalid memory profile path, got nil")
	}
}
