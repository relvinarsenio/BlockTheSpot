[![Build status](https://ci.appveyor.com/api/projects/status/31l6ynm0a1fhr2vs/branch/master?svg=true)](https://ci.appveyor.com/project/mrpond/blockthespot/branch/master) [![Discord](https://discord.com/api/guilds/807273906872123412/widget.png)](https://discord.gg/p43cusgUPm)


## BlockTheSpot is back! 

Doing things without modify xpui.spa, you don't need to running any .bat/powershell script!!

Since BlockTheSpot will modify them (in memory) on the fly!!

A multi-purpose adblocker and skip-bypass for the Windows Spotify desktop application

Please support Spotify by purchasing premium

#### Just copy dpapi.dll and config.ini into spotify installation folder.

### Killer feature built-in developer mode [Develop->Show Debug Window]
- enable/disable feature by yourself in realtime and on demand
- choose old/new theme(YLX)
- enable right sidebar
- default hide upgrade button on top bar

and much more...


[![Build status](https://ci.appveyor.com/api/projects/status/31l6ynm0a1fhr2vs/branch/master?svg=true)](https://ci.appveyor.com/project/mrpond/blockthespot/branch/master)  [![Discord](https://discord.com/api/guilds/807273906872123412/widget.png)](https://discord.gg/p43cusgUPm)

<center>
    <h1 align="center">BlockTheSpot</h1>
    <h4 align="center">A multi-purpose adblocker and skip-bypass for the <strong>Windows</strong> Spotify desktop application.</h4>
    <h5 align="center">Please support Spotify by purchasing premium</h5>
    <p align="center">
        <strong>Last updated:</strong> 29 October 2021<br>
        <strong>Last tested version:</strong> 1.1.87.612.gf8d110e2
    </p> 
</center>

#### Important checks before installing:
0. Update Windows, update Spotify and update BlockTheSpot
1. Go to "Windows Security" -> "Virus & Threat Protection"
2. Click "Allowed threats" -> "Remove all allowed threats"

### Features:
* Unlocks all premium features except downloads.
* Lives through Spotify updates. No need to patch Spotify after every update anymore.

#### Experimental features from developer mode
- Enable/disable feature by yourself in realtime and on demand.
- Choose old/new theme(YLX).
- Enable right sidebar.
- Hide upgrade button on top bar.

:warning: This mod is for the [**Desktop Application**](https://www.spotify.com/download/windows/) of Spotify on Windows only and **not the Microsoft Store version**.

### Installation/Update:
* Just download and run [BlockTheSpot.bat](https://raw.githack.com/mrpond/BlockTheSpot/master/BlockTheSpot.bat)  

or

#### Fully automated installation via PowerShell

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-Expression "& { $(Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/mrpond/BlockTheSpot/master/install.ps1') } -UninstallSpotifyStoreEdition -UpdateSpotify"
```

#### Manual installation

1. Browse to your Spotify installation folder `%APPDATA%\Spotify`
2. Rename `dpapi.dll` to `dpapi_bak.dll`. The naming is important.
3. Download `chrome_elf.zip` from [releases](https://github.com/mrpond/BlockTheSpot/releases)
4. Unzip `dpapi.dll` and `config.ini` to Spotify directory. 

### Uninstall:
* Just run [uninstall.bat](https://raw.githack.com/mrpond/BlockTheSpot/master/uninstall.bat)
or
* Reinstall Spotify

### Additional Notes:

* Installation script automatically detects if your Spotify client version is supported, or not. If the version is not supported, you will be prompted to update your Spotify client. To enforce client update, supply an optional parameter `UpdateSpotify` to the installation script. 
* [Spicetify](https://github.com/khanhas/spicetify-cli) users will need to reapply BlockTheSpot after applying a Spicetify themes/patches.
* If the automatic install/uninstall scripts do not work, please contact [Nuzair46](https://github.com/Nuzair46).
* For more support and discussions, join our [Discord server](https://discord.gg/p43cusgUPm).





