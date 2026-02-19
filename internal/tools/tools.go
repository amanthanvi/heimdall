//go:build tools

package tools

import (
	_ "github.com/awnumar/memguard"
	_ "github.com/charmbracelet/bubbles"
	_ "github.com/charmbracelet/bubbletea"
	_ "github.com/charmbracelet/huh"
	_ "github.com/charmbracelet/lipgloss"
	_ "github.com/google/uuid"
	_ "github.com/pelletier/go-toml/v2"
	_ "golang.org/x/crypto/argon2"
	_ "google.golang.org/grpc"
	_ "google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"
)
