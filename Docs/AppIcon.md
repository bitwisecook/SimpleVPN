# App icon

`SimpleVPN/SimpleVPN.icon` is the editable Icon Composer source and the app's
only authored icon asset. Xcode compiles it into the layered system icon and the `.icns`
fallback. `project.yml` selects it through
`ASSETCATALOG_COMPILER_APPICON_NAME: SimpleVPN`.

The foreground is a custom vector padlock projected in 3D: 24° yaw, 18° backward
lean, and 13° counterclockwise tilt. Its bottom-right corner comes forward,
revealing the right side and underside. Four SVG assets describe the face,
body depth, shackle face, and shackle depth, including the keyhole's inner wall.
The larger white glass body stands out against the blue; the shackle uses a
clearer material with stronger refraction and individually lit glass surfaces.
All three groups share a 48-point left and 32-point upward composition offset
for optical centering. Native outside specular highlights on the face and
shackle provide the polished reflections; no highlights are painted into assets.
The blue gradient is the document background; macOS supplies the squircle mask.
Glass, specular lighting, refraction and shadow are native Icon Composer effects.
Dark mode uses a deeper blue background. Tinted mode increases the foreground
opacity to keep the shape clear.

Open `SimpleVPN/SimpleVPN.icon` in Icon Composer to adjust the material or layout.
Change the geometry in `Tools/generate-icon-geometry.py`, then run
`python3 Tools/generate-icon-geometry.py` from the repository root to regenerate
the four SVG assets. The script uses only the Python standard library and is
not part of the build; generated assets are committed. The canvas is 1024 × 1024.
The document uses the refractivity controls available in Icon Composer 2 or later;
the compiler also generates the macOS 26 rendition.

To render a preview from the repository root:

```sh
ICTOOL="$(dirname "$(xcode-select -p)")/Applications/Icon Composer.app/Contents/Executables/ictool"
mkdir -p build/icon-previews
"$ICTOOL" SimpleVPN/SimpleVPN.icon --export-image \
  --output-file build/icon-previews/Default.png --platform macOS \
  --rendition Default --width 1024 --height 1024 --scale 1
```

Other renditions are `Dark`, `TintedLight`, `TintedDark`, `ClearLight`, and
`ClearDark`. Add `--design-generation 26` to inspect the macOS 26 rendering.
Regenerate the Xcode project with `xcodegen generate` after changing project
configuration; do not edit the generated project.

The About window reads `NSApp.applicationIconImage`, so it follows the bundle
icon automatically. Finder and the Dock use the same compiled app icon. The
menu bar's monochrome open/closed lock is a connection-status symbol.

The installer uses `Installer/InstallerIcon.icon`, generated from this same
document and its assets with a small install bubble above the lock. It preserves
the main icon's dark and tinted appearances. After editing the main icon, run
`python3 Tools/generate-installer-icon.py`; `Tools/test-installer.sh` checks that
the generated helper icon stays in sync. The installer target compiles its own
layered icon and `.icns` fallback for Finder, dialogs and its sole Dock tile.

`Docs/Assets/AppIcon.png`, `AppIcon-Dark.png`, and `SimpleVPN-logo.svg` are
generated exports of this source. The README selects the light or dark PNG.
The standalone SVG embeds the native PNG rendering to preserve the glass effects;
the editable vector geometry remains in the `.icon` package. Regenerate exports
after changing the icon:

```sh
python3 Tools/export-app-icon.py
# Also update an existing workspace copy, when present:
python3 Tools/export-app-icon.py --workspace-logo ../SimpleVPN-logo.svg
```
