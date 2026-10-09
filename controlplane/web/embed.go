// Package web embeds the built React UI (vite outDir points here).
package web

import "embed"

//go:embed all:dist
var Dist embed.FS

// DistDir is "dist": callers need fs.Sub(Dist, DistDir) to serve without the "dist/" prefix.
const DistDir = "dist"
