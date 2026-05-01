package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/logger"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:             "SilentShield-Windows",
		Width:             1280,
		Height:            850,
		MinWidth:          900,
		MinHeight:         700,
		DisableResize:     false,
		Fullscreen:        false,
		Frameless:         false,
		StartHidden:       false,
		LogLevel:          logger.INFO,
		LogLevelProduction: logger.ERROR,
		BackgroundColour:  &options.RGBA{R: 240, G: 248, B: 255, A: 1},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:  app.startup,
		OnShutdown: app.shutdown,
		WindowStartState: options.Normal,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewUserDataPath: "",
			ZoomFactor:          1.0,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
