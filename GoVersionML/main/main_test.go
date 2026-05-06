package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// BenchmarkEndToEnd measures the performance of the full processing pipeline.
// Run this with the Run-Benchmark.ps1 script, or manually:
//
//	go test -bench=BenchmarkEndToEnd -benchmem -count=5 > results.txt
//	benchstat results.txt

func TestRun_NoArgs(t *testing.T) {
	err := run([]string{})
	if err == nil {
		t.Error("expected error for no args (missing input file), got nil")
	}
}

func TestRun_InvalidFlag(t *testing.T) {
	err := run([]string{"--invalid-flag-that-does-not-exist"})
	if err == nil {
		t.Error("expected error for invalid flag, got nil")
	}
}

func TestRun_InvalidCPUProfile(t *testing.T) {
	// Use an invalid path for CPU profile that cannot be created
	// E.g. a directory that does not exist
	err := run([]string{"-cpuprofile", "nonexistent_dir/cpu.prof", "dummy_input.json"})
	if err == nil {
		t.Error("expected error for invalid CPU profile path, got nil")
	}
}

func TestRun_PipelineFailure(t *testing.T) {
	// A file that does not exist should cause pipeline to fail
	err := run([]string{"-m", "dummy_model.json", "nonexistent_input.json"})
	if err == nil {
		t.Error("expected pipeline to fail for nonexistent file, got nil")
	}
}

func TestMain_Exit1_On_Error(t *testing.T) {
	if os.Getenv("TEST_MAIN_CRASHER") == "1" {
		// Mock os.Args to fail validation
		os.Args = []string{"goversionML.exe", "--invalid-flag"}
		main()
		return
	}

	// Re-run the test binary as a subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Exit1_On_Error")
	cmd.Env = append(os.Environ(), "TEST_MAIN_CRASHER=1")
	err := cmd.Run()

	// We expect an ExitError because the command should exit with 1
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return // Expected behavior
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestMain_Exit0_On_Help(t *testing.T) {
	if os.Getenv("TEST_MAIN_CRASHER") == "1" {
		// Mock os.Args to trigger help and exit 0
		os.Args = []string{"goversionML.exe", "-h"}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Exit0_On_Help")
	cmd.Env = append(os.Environ(), "TEST_MAIN_CRASHER=1")
	err := cmd.Run()

	// We expect a successful exit (status 0)
	if err != nil {
		t.Fatalf("process ran with err %v, want exit status 0", err)
	}
}

func TestRun_Success(t *testing.T) {
	modelPath := filepath.Join("..", "Xgboost", "botnet_xgboost.json")
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		t.Skipf("Model file %s not found, skipping success test", modelPath)
	}

	// Create a temp directory
	tmpDir := t.TempDir()

	// Create a small valid test file
	testFile := filepath.Join(tmpDir, "test.ndjson")
	validJSON := `{"first":"2026-03-17T12:00:00.000","last":"2026-03-17T12:00:01.000","in_packets":10,"in_bytes":100,"proto":6,"tcp_flags":"S","src_port":1234,"dst_port":80,"src4_addr":"192.168.1.1","dst4_addr":"10.0.0.1"}` + "\n"
	if err := os.WriteFile(testFile, []byte(validJSON), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	cpuProf := filepath.Join(tmpDir, "cpu.prof")
	memProf := filepath.Join(tmpDir, "mem.prof")
	outTxt := filepath.Join(tmpDir, "out.txt")

	// Store original stdout/stderr to avoid pollution
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
		"-m", modelPath,
		"-cpuprofile", cpuProf,
		"-memprofile", memProf,
		"-o", outTxt,
		testFile,
	}

	err = run(args)
	if err != nil {
		t.Errorf("expected successful run, got error: %v", err)
	}

	// Verify files were created
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

	// Memprofile is a path in a nonexistent directory to trigger os.Create error
	badMemProf := filepath.Join(tmpDir, "does_not_exist", "mem.prof")

	args := []string{
		"-m", modelPath,
		"-memprofile", badMemProf,
		testFile,
	}

	err := run(args)
	if err == nil {
		t.Error("expected error for invalid memory profile path, got nil")
	}
}

func TestRun_InvalidOutput(t *testing.T) {
	// A nonexistent directory for the output file
	err := run([]string{"-o", "nonexistent_dir/output.txt", "dummy_input.json"})
	if err == nil {
		t.Error("expected error for invalid output path, got nil")
	}
}
