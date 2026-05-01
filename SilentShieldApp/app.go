package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	runtime2 "github.com/wailsapp/wails/v2/pkg/runtime"
)

const SERVER_PORT = 12701

// App struct
type App struct {
	ctx         context.Context
	serverCmd   *exec.Cmd
	serverReady bool
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called at application startup
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	fmt.Println("[SilentShield] Starting application...")
	go a.startNodeServer()
}

// shutdown is called at application shutdown
func (a *App) shutdown(ctx context.Context) {
	fmt.Println("[SilentShield] Shutting down...")
	if a.serverCmd != nil && a.serverCmd.Process != nil {
		if runtime.GOOS == "windows" {
			exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", a.serverCmd.Process.Pid)).Run()
		} else {
			a.serverCmd.Process.Kill()
		}
	}
}

func (a *App) startNodeServer() {
	fmt.Println("[SilentShield] Looking for Node.js...")

	// Find node executable
	nodePath, err := exec.LookPath("node")
	if err != nil {
		fmt.Println("[SilentShield] ERROR: Node.js not found in PATH. Please install Node.js first.")
		runtime2.Quit(a.ctx)
		return
	}
	fmt.Println("[SilentShield] Node.js found at:", nodePath)

	// Find server.js
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)

	// Try multiple possible paths
	possiblePaths := []string{
		filepath.Join(execDir, "src", "js", "server.js"),
		filepath.Join(execDir, "..", "src", "js", "server.js"),
		filepath.Join(execDir, "app", "src", "js", "server.js"),
		filepath.Join("src", "js", "server.js"),
	}

	serverPath := ""
	for _, p := range possiblePaths {
		absPath, _ := filepath.Abs(p)
		if _, err := os.Stat(absPath); err == nil {
			serverPath = absPath
			break
		}
	}

	if serverPath == "" {
		fmt.Println("[SilentShield] ERROR: server.js not found. Searched paths:")
		for _, p := range possiblePaths {
			fmt.Println("  -", p)
		}
		runtime2.Quit(a.ctx)
		return
	}
	fmt.Println("[SilentShield] Server script:", serverPath)

	// Start Node.js server
	a.serverCmd = exec.Command(nodePath, serverPath)
	a.serverCmd.Stdout = os.Stdout
	a.serverCmd.Stderr = os.Stderr

	if runtime.GOOS == "windows" {
		a.serverCmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: 0x08000000, // CREATE_NO_WINDOW
		}
	}

	err = a.serverCmd.Start()
	if err != nil {
		fmt.Println("[SilentShield] ERROR: Failed to start server:", err.Error())
		runtime2.Quit(a.ctx)
		return
	}

	fmt.Println("[SilentShield] Node.js server started (PID:", a.serverCmd.Process.Pid, ")")

	// Wait for server to be ready (up to 30 seconds)
	fmt.Println("[SilentShield] Waiting for server to start...")
	for i := 0; i < 60; i++ {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/status", SERVER_PORT))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				a.serverReady = true
				fmt.Println("[SilentShield] Server is ready! Opening UI...")

				// Wait a moment then navigate
				time.Sleep(500 * time.Millisecond)
				runtime2.WindowSetTitle(a.ctx, "SilentShield-Windows - Zero-Footprint Protection")
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println("[SilentShield] ERROR: Server startup timeout")
	runtime2.Quit(a.ctx)
}

// Greet returns a greeting
func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, welcome to SilentShield!", name)
}

// GetServerStatus returns whether the backend server is running
func (a *App) GetServerStatus() map[string]interface{} {
	return map[string]interface{}{
		"ready": a.serverReady,
		"port":  SERVER_PORT,
	}
}
