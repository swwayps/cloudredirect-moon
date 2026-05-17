# CloudRedirect

""Steam Cloud"" for 'lua' games. Now for Linux!

> ****This software is experimental and under active development.**** The underlying techniques are fairly insane. What this software tries to do is nuts to attempt. This software could damage your save files and probably will! It could overwrite your saves, cause weird conflicts, make your saves disappear, make you cry. Back up any saves you care about before using this software.

>****DO NOT USE THIS SOFTWARE IF YOU ARE AN IDIOT. Do not use this if you do not actively want cloud saves for "lua" games. If all you care about is the Steam Cloud error, disable Steam Cloud in properties for that game.****

## What it does

Something like Steam Cloud, but for games you cannot use with actual Steam Cloud for because, uhh, reasons?

What this tool does is redirect Steam Cloud requests for games that are 'injected' to Google Drive/OneDrive/a local folder, including AutoCloud games. Everything is native inside the Steam Client, but the actual data is read/written to and from your cloud account. This was much harder to do than just redirecting read/write to an AppID that your account owns, but it was fun to make. It also is less likely to piss off Valve.

This isn't uploading your save files manually or something silly like that. It's the real deal. Steam Cloud, but going to a cloud provider and not Valve.

The tool also has a function to reset the progress of games (useful for auto cloud games that you want to start over in) and a tool to scan SteamTools games for the pollution described above. ****DO NOT USE THOSE FUNCTIONS IF YOU DO NOT KNOW WHAT YOU ARE DOING. YOU WILL END UP DELETING YOUR SAVE. WHILE THE TOOL DOES TAKE A BACKUP AND CAN EASILY RESTORE IT, YOU STILL SHOULD NOT USE THAT TOOL UNLESS YOU KNOW WHAT YOU ARE DOING.****

Please treat the cloud 'folder' on your cloud provider the same way you would treat Steam Cloud itself. If you delete that folder from Google Drive/OneDrive without disabling the provider in CloudRedirect, expect bad things to happen.

CloudRedirect is good software. It's clever.

## How it works

CloudRedirect consists of a C++ DLL and a WPF companion app:

1. The companion app patches the SteamTools payload to load the CloudRedirect DLL at startup.
2. The DLL hooks Steam's internal cloud save RPC handlers via ~~vtable interception~~ black magic.
3. When a lua game attempts to read or write cloud save data, the DLL intercepts the calls and redirects them to a local cache directory. If the game is owned, the game uses normal Steam Cloud as expected. If a lua is present that only unlocks DLC, the game will use normal Steam Cloud.
4. More dark magic occurs and the saves are synced to or from your chosen cloud provider. This all is visible in the Steam UI and looks identical to normal Steam Cloud functionality.

For Linux, it consists of a flatpak app and a component that gets loaded during Steam startup. It more or less works the same way as the Windows version conceptually, but for Linux.

## Supported cloud providers

- **Google Drive**
- **OneDrive**
- **Local folder / mapped drive** -- by request of literally one user.

## Usage (Windows)

Make sure you are on the latest version of Steam. That is the only supported versions of Steam. 

Grab the latest release from the [Releases page](https://github.com/Selectively11/CloudRedirect/releases).

Note that you do not need to run STFixer with this. The 'Capcom save fix' is always present with this tool. 

Run the EXE. In Setup, hit 'Run All Patches'. Go to the Cloud Provider tab, select your provider. If it is a cloud provider, hit 'Sign In' and sign in. 

That's it. Go launch Steam. Your games should start syncing now. You may have errors if your userdata folder was filled with garbage by SteamTools and the game is a Steam AutoCloud save. In that case, you need to identify which files belong in that folder and which files belong to another game and clean it up. 

## Usage (Linux)

Make sure you are also on the latest SLSSteam and have DisableCloud set to No. You also need to have your non-owned games listed under AdditionalApps in SLS.

<pending an update, standby>

## Building from source (Windows)

### Prerequisites

- Visual Studio 2022 (or Build Tools) with the C++ and .NET 8 workloads
- CMake 3.20+

### Build

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

This builds both the C++ DLL (`build/Release/cloud_redirect.dll`) and publishes the WPF app (`ui/bin/publish/CloudRedirect.exe`). The DLL is automatically embedded into the executable.

Or don't build it? Building Windows apps is pain.

## Building from source (Linux)

If you are using Linux and want to build this, I trust that you can figure it out.
