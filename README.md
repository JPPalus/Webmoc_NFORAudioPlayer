# webmoc
A javascript small-form audio player, inspired by moc (music on console).

The `player.html` file is enough for basic functionality.
Album art is provided by `pic.php` ; this requires a working PHP engine along with `ffmpeg`, which is `exec`'d as a UNIX-shell utility.

The player itself expects an adjacent `music/` folder, which should contain a `playlists/` subdirectory with all available playlists in [M3U format](https://en.wikipedia.org/wiki/M3U).
