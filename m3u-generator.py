from pathlib import Path
import sys

VALID_FILES = ['.mp3', '.wav', '.flacc', '.mid']
SITE_ROOT = 'https://malekith.fr/VoxCasterPublicae/'

# delete old playlists
for pattern in sys.argv[1:]:
    for path in Path(sys.argv[1]).rglob('*'):
        if path.is_dir():
            old_playlist = Path(str(path) + '/playlist.m3u')
            if old_playlist.exists():
                old_playlist.unlink()
# including the root_folder
old_playlist = Path('./playlist.m3u')
if old_playlist.exists():
    old_playlist.unlink()

for pattern in sys.argv[1:]:
    for path in Path(sys.argv[1]).rglob('*'):
        for extension in VALID_FILES:
            # construct new playlists
            if str(path).endswith(extension):
                root_folder = path.parent
                playlist_filename = str(root_folder) + '/playlist.m3u'
                playlist = open(playlist_filename, "a+")
                playlist.write(SITE_ROOT + str(path) + '\n')
                playlist.close()
