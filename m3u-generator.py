import glob
from natsort import natsorted

VALID_FILES = ['.mp3', '.wav', '.flac', '.mid', '.ogg']
SITE_ROOT = 'https://malekith.fr/VoxCasterPublicae/'

files = natsorted(glob.glob('**/*',recursive=True))

playlist = ''

for file in files:
    for authorized_filetype in VALID_FILES:
        if file.endswith(authorized_filetype) and file != "playlist.m3u":
            playlist += SITE_ROOT + file + '\n'

f = open("playlist.m3u", "w")
f.write(playlist)
f.close()
