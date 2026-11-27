// Package application discovers installed desktop applications and running
// processes for split tunnel attribution.
//
// Discovery parses freedesktop desktop entries directly. It never runs an
// entry's commands, never loads icons and never invokes flatpak, snap, gio or
// systemctl. Linux process inspection reads /proc without elevation; the
// desktop entry parser itself is portable.
package application
