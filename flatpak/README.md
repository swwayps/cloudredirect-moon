# CloudRedirect Flatpak

This directory contains the Flatpak manifest for building CloudRedirect's Linux UI.

## Architecture

The Flatpak packages:
- **cloud-redirect-ui**: Qt6/QML application for configuration and deployment
- **cloud_redirect.so**: Bundled as a data file (not executed in sandbox)
- **cloud_redirect_cli**: CLI tool for cloud provider operations (list/delete remote apps)

The UI app copies `cloud_redirect.so` and `cloud_redirect_cli` from the Flatpak bundle
to the user's system (`~/.local/share/SLSsteam/`) and patches `steam.sh` to load the
`.so` via `LD_AUDIT`. The CLI must be in the same directory as the `.so` because it
loads the library via `dlopen`.

## Requirements

- Native Steam installation (not Steam Flatpak)
- SLSsteam/Accela installed
- Flatpak and flatpak-builder

## Building

### Prerequisites

```bash
# Install Flatpak SDK
flatpak install flathub org.kde.Platform//6.7 org.kde.Sdk//6.7
```

### Build the native binaries first

The 32-bit `cloud_redirect.so` and `cloud_redirect_cli` must be built separately:

```bash
# On a 32-bit environment or with multilib
cd /path/to/CloudRedirect-Unified
mkdir build-linux && cd build-linux
cmake .. -DCMAKE_BUILD_TYPE=Release
make cloud_redirect cloud_redirect_cli

# Copy to flatpak directory
cp cloud_redirect.so cloud_redirect_cli ../flatpak/
```

### Build the Flatpak

```bash
cd flatpak
flatpak-builder --user --install --force-clean build-dir org.cloudredirect.CloudRedirect.yml
```

### Run

```bash
flatpak run org.cloudredirect.CloudRedirect
```

## Publishing

To publish to Flathub:
1. Fork https://github.com/flathub/flathub
2. Create a branch with your app ID
3. Add your manifest
4. Submit a PR

## Notes

- The `.so` cannot run inside the Flatpak sandbox (LD_AUDIT is stripped)
- The UI has `--filesystem=home` permission to deploy the `.so` outside the sandbox
- Users must use native Steam, not Steam Flatpak
