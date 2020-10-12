<?php

//Disable error report for undefined superglobals
error_reporting( error_reporting() & ~E_NOTICE );

$allow_direct_link = true; // Set to false to only allow downloads and not direct link
$allow_show_folders = true; // Set to false to hide all subdirectories

$disallowed_patterns = ['*.php'];  // must be an array.  Matching files not allowed to be uploaded
$hidden_patterns = ['*.php','.*', 'playlist.m3u']; // Matching files hidden in directory index
$allowed_patterns = ['*.mp3', '*.wav', '*.flac', '*.ogg', '*.mid', '*.m3u']; // Matching files hidden in directory index

$PASSWORD = '';  // Set the password, to access the file manager... (optional)

if($PASSWORD) {
	session_start();
	if(!$_SESSION['_sfm_allowed']) {
		// sha1, and random bytes to thwart timing attacks.  Not meant as secure hashing.
		$t = bin2hex(openssl_random_pseudo_bytes(10));
		if($_POST['p'] && sha1($t.$_POST['p']) === sha1($t.$PASSWORD)) {
			$_SESSION['_sfm_allowed'] = true;
			header('Location: ?');
		}
		echo '<html><body><form action=? method=post>PASSWORD:<input type=password name=p autofocus/></form></body></html>';
		exit;
	}
}

// must be in UTF-8 or `basename` doesn't work
setlocale(LC_ALL,'en_US.UTF-8');

$tmp_dir = dirname($_SERVER['SCRIPT_FILENAME']);
if(DIRECTORY_SEPARATOR==='\\') $tmp_dir = str_replace('/',DIRECTORY_SEPARATOR,$tmp_dir);
$tmp = get_absolute_path($tmp_dir . '/' .$_REQUEST['file']);

if($tmp === false)
err(404,'File or Directory Not Found');
if(substr($tmp, 0,strlen($tmp_dir)) !== $tmp_dir)
err(403,"Forbidden");
if(strpos($_REQUEST['file'], DIRECTORY_SEPARATOR) === 0)
err(403,"Forbidden");
if(preg_match('@^.+://@',$_REQUEST['file'])) {
	err(403,"Forbidden");
}

// XSRF check
if(!$_COOKIE['_sfm_xsrf'])
setcookie('_sfm_xsrf',bin2hex(openssl_random_pseudo_bytes(16)));
if($_POST) {
	if($_COOKIE['_sfm_xsrf'] !== $_POST['xsrf'] || !$_POST['xsrf'])
	err(403,"XSRF Failure");
}

$file = $_REQUEST['file'] ?: '.';

if($_GET['do'] == 'list') {
	if (is_dir($file)) {
		$directory = $file;
		$result = [];
		$files = array_diff(scandir($directory), ['.','..']);
		foreach ($files as $entry) if (is_entry_allowed($entry, $allow_show_folders, $allowed_patterns, $hidden_patterns)) {
			$i = $directory . '/' . $entry;
			$stat = stat($i);
			$result[] = [
				'mtime' => $stat['mtime'],
				'size' => $stat['size'],
				'name' => basename($i),
				'path' => preg_replace('@^\./@', '', $i),
				'is_dir' => is_dir($i),
				'is_readable' => is_readable($i),
				'is_writable' => is_writable($i),
				'is_executable' => is_executable($i),
			];
		}
		usort($result,function($f1,$f2){
			$f1_key = ($f1['is_dir']?:2) . $f1['name'];
			$f2_key = ($f2['is_dir']?:2) . $f2['name'];
			return $f1_key > $f2_key;
		});
	} elseif (is_file($file)) {
		$result = [];
		$stat = stat($file);
		$result[] = [
			'mtime' => $stat['mtime'],
			'size' => $stat['size'],
			'name' => basename($file),
			'path' => preg_replace('@^\./@', '', $file),
			'is_dir' => is_dir($file),
			'is_readable' => is_readable($file),
			'is_writable' => is_writable($file),
			'is_executable' => is_executable($file),
		];
	} else {
		err(412,"Not a file");
	}
	echo json_encode(['success' => true, 'is_writable' => is_writable($file), 'results' =>$result]);
	exit;

} elseif (isset($_GET['get_album_art'])) {
	$sfile = escapeshellarg($_GET["track"]);
	$img = shell_exec("ffmpeg -i $sfile -f image2pipe pipe:1 2>/dev/null");
	header("Content-type: image/*");
	if (strlen($img) != 0)
	echo($img);
	else // not black pixel.
	// echo(base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNU+g8AAUkBI5mqlHIAAAAASUVORK5CYII="));
	echo "null";
	return;

} elseif (isset($_GET['get_formated_audio_metadata'])) {
	$sfile = escapeshellarg($_GET["track"]);
	echo shell_exec("ffmpeg -i $sfile -f ffmetadata pipe:1 2>/dev/null");
	return;

} elseif (isset($_GET['get_audio_technical_data'])) {
	$sfile = escapeshellarg($_GET["track"]);
	$data = shell_exec("ffmpeg -i $sfile 2>&1");
	header("Content-type: text/*");
	echo $data;
	return;

} elseif ($_GET['do'] == 'download') {
	foreach($disallowed_patterns as $pattern)
	if(fnmatch($pattern, $file))
	err(403,"Files of this type are not allowed.");

	$filename = basename($file);
	$finfo = finfo_open(FILEINFO_MIME_TYPE);
	header('Content-Type: ' . finfo_file($finfo, $file));
	header('Content-Length: '. filesize($file));
	header(sprintf('Content-Disposition: attachment; filename=%s',
	strpos('MSIE',$_SERVER['HTTP_REFERER']) ? rawurlencode($filename) : "\"$filename\"" ));
	ob_flush();
	readfile($file);
	exit;
}

function is_entry_allowed($entry, $allow_show_folders, $allowed_patterns, $hidden_patterns) {

	if ($entry === basename(__FILE__)) {
		return false;
	}
	// oui
	foreach($hidden_patterns as $hidden) {
		if(fnmatch($hidden, $entry)) {
			return false;
		}
	}

	if (is_dir($entry) && $allow_show_folders) {
		return true;
	}

	foreach($allowed_patterns as $pattern) {
		if(fnmatch($pattern, $entry)) {
			return true;
		}
	}

	// subfolder hack :(
	if(!fnmatch("*.*", $entry) && !is_file($entry)) {
		return true;
	}

	return false;
}

function get_absolute_path($path) {
	$path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path);
	$parts = explode(DIRECTORY_SEPARATOR, $path);
	$absolutes = [];
	foreach ($parts as $part) {
		if ('.' == $part) continue;
		if ('..' == $part) {
			array_pop($absolutes);
		} else {
			$absolutes[] = $part;
		}
	}
	return implode(DIRECTORY_SEPARATOR, $absolutes);
}

?>

<!DOCTYPE html>
<html><head>
	<meta http-equiv="content-type" content="text/html; charset=utf-8">

	<style>
	.aquila {
		width: 30px;
	}


	body {
		font-family: "lucida grande",
		"Segoe UI",
		Arial,
		sans-serif;
		font-size:14px;
		color: GoldenRod;
		width: 1024;
		padding: 1em;
		margin:0;
		background-color: #222222;
	}

	th {
		font-weight: bold;
		color: GoldenRod;
		background-color: #025202;
		padding: .5em 1em .5em .2em;
		text-align: left;
		cursor:pointer;
		user-select: none;
	}

	th .indicator {
		margin-left: 6px;
		color: GoldenRod;
	}

	a {
		cursor:pointer;
	}

	thead {
		border-top: 5px solid #018a30;
		border-bottom: 5px solid #018a30;
		border-left: 5px solid #018a30;
		border-right: 5px solid #018a30;
	}

	#list {
		border-top: 5px solid #018a30;
		border-bottom: 5px solid #018a30;
		border-left: 5px solid #018a30;
		border-right: 5px solid #018a30;
	}

	label {
		display:block;
		font-size:11px;
		color:#555;
	}

	footer {
		font-size:11px;
		color:#bbbbc5;
		padding:4em 0 0;
		text-align: left;
	}

	footer a, footer a:visited {
		color:#bbbbc5;
	}

	#overlay {
		pointer-events:none;
		position: absolute;
		top: 2px;
		right: 20px;
		padding-top: 10px;
		height: 250px;
	}

	#album_art {
		visibility: hidden;
		outline: none;
		pointer-events:none;
		position: absolute;

		top: 123px;
		left: 15px;
		width: 120px;
		height: 120px;

		border-bottom: 2px outset GoldenRod;
		border-top: 3px outset GoldenRod;
		border-right: 3px outset GoldenRod;
		border-left: 3px outset GoldenRod;
	}

	#top {
		position: absolute;
		top: 220px;
		height: 60px;
		color: GoldenRod;
	}

	-webkit-scrollbar {
		/* display: none; */
	}

	#mid {
		position: absolute;
		left: 15px;
		right: 15px;
		top: 280px;
		/* display: block; */
		height: 70%;
		overflow-y: auto;
		overflow-x: auto;
		scrollbar-width: thin;
		scrollbar-color: #4f420f #222222;
	}

	#breadcrumb {
		font-weight: bold;
		padding-top:34px;
		font-size:15px;
		color: red;
		display:inline-block;
		float:left;
	}

	#audio_block {
		position: absolute;
	}

	/* firefox only */
	#audio_player {
		position: absolute;
		background-color: Gold;
		width: 50%;
		border-right: 2px inset #484015;
	}

	#midi_player {
		visibility: hidden;
		position: absolute ;
		background-color: #484015;
		height: 39px;
		width: 50%;

		border-right: 2px inset #484015;
	}

	#midi_progressbar {
		margin-left: 60px;
		margin-right: 120px;
		top : 18px;
		background: rgba(255,255,255,0.1);
		justify-content: flex-start;
		border-radius: 10px;
		align-items: center;
		position: relative;
		height: 5px;
	}

	#bar {
		top : 0px;
		background: DeepSkyBlue;
		justify-content: flex-start;
		border-radius: 10px;
		align-items: center;
		position: relative;
		height: 5px;
		width: 0%;
	}

#midi_bar_ball {
		position: absolute;
		float: right;
		right: -5px;
		top: -4px;
		height: 13px;
		width: 13px;
		background-color: FloralWhite;
		border-radius: 50%;
		display: inline-block;
}

#midi_player_time {
		position: absolute;
		right: 10px;
		/* top: 10px; */
		top: 12px;
		background-color: #484015;

		height: 20px;
		/* width: 90px; */
		resize: none;
		font-family: "lucida grande", "Segoe UI", Arial, sans-serif;
		font-size: 14px;

		font-weight: bold;
		color: FloralWhite;
	}

	#midi_play {
		position: absolute;
		left: 13px;
		top: 6px;
		width: 28px;
	}

	#midi_pause {
		visibility: hidden;
		position: absolute;
		left: 16px;
		top: 8px;
		width: 23px;
	}

	#buttons_raw {
		position: absolute;
		top: 79px;
		background-color: #222222;
		width: 50%;

		border-right: 2px solid #222222;
	}

	#checkbox_raw {
		/* position: absolute; */
		float: right;
		/* top: 79px; */
		background-color: #222222;
		/* width: 250px; */

		border-right: 2px solid #222222;
	}

	#audio_info {
		position: absolute;
		top: 55px;

		resize: none;
		font-family: "lucida grande", "Segoe UI", Arial, sans-serif;
		font-size: 14px;
		height: 20px;
		width: 50%;
		background-color: Maroon;
		font-weight: bold;
		color: FloralWhite;
		border-top: 0px inset DarkRed;
		border-bottom: 0px inset DarkRed;
		border-left: 0px inset DarkRed;
		border-right: 0px inset DarkRed;
	}

	#speed {
		pointer-events:none;
		position: absolute;

		top: 14px;
		left: 50%;
		padding-left: 20px;
		height: 39px;
	}

	#speed_data {
		cursor: text;
		resize: none;

		font-family: "lucida grande", "Segoe UI", Arial, sans-serif;
		font-size: 7px;
		text-align: center;

		position: absolute;
		top: 42px;
		left: 50%;
		margin-left: 22px;
		height: 10px;
		width: 20px;
		overflow-x: hidden;
		overflow-y: hidden;

		background-color: #222222;
		font-weight: bold;
		color: GoldenRod;
	}

	#play_next {
		/* position: absolute; */
		top: 10px;
		 /* left: 20px; */
		height: 20px;
		padding-right: 20px;
		margin-top: 5px;
	}

	#backward {
		/* position: absolute; */
		top: 10px;
		 /* left: 20px; */
		height: 20px;
		padding-right: 10px;
	}

	#forward {
		/* position: absolute; */
		top: 10px;
		 /* left: 20px; */
		height: 20px;
		padding-right: 20px;
	}

	#speedm {
		/* position: absolute; */
		top: 10px;
		 /* left: 20px; */
		height: 20px;
		padding-right: 10px;
	}

	#speed_normal {
		/* position: absolute; */
		top: 10px;
		 /* left: 20px; */
		height: 20px;
		padding-right: 10px;
	}

	#speedp {
		/* position: absolute; */
		top: 10px;
		 /* left: 20px; */
		height: 20px;
		padding-right: 40px;
	}

	#is_autoplay {
		/* float: right; */
	}

	#is_loop {
		/* float: right; */
	}

	#is_random {
		/* float: right; */
	}

	#audio_data {
		cursor: text;
		resize: none;

		font-family: "lucida grande", "Segoe UI", Arial, sans-serif;
		font-size: 14px;

		position: absolute;
		top: 35px;
		right: 26px;
		padding-top: 4px;
		height: 185px;
		width: 320px;
		overflow-x: hidden;
		overflow-y: scroll;

		background-color: #2e0b0b;
		font-weight: bold;
		color: FloralWhite;
	}

	#audio_data_2,  #audio_data_1, #audio_data_3 {
		resize: none;
		font-family: "lucida grande", "Segoe UI", Arial, sans-serif;
		font-size: 14px;

		width: 298px;

		background-color: #2e0b0b;
		font-weight: bold;
		color: FloralWhite;
	}

	#audio_data_1 {
		visibility: hidden;
		border-bottom: 3px inset DarkRed;
		border-right: 3px inset DarkRed;
		border-left: 3px inset DarkRed;
	}

	#audio_data_2 {
		visibility: hidden;
		border-right: 3px inset DarkRed;
		border-left: 3px inset DarkRed;
		border-bottom: 3px inset DarkRed;
	}

	#audio_data_3 {
		visibility: hidden;
		border-bottom: 3px inset DarkRed;
		border-top: 3px inset DarkRed;
		border-right: 3px inset DarkRed;
		border-left: 3px inset DarkRed;
	}

	#folder_actions {
		width: 50%;
		float:right;
	}

	a {
		text-decoration;
	}

	a, a:visited {
		text-decoration: none;
		color: GoldenRod;
	}

	a:hover {
		text-decoration: none;
		color: GoldenRod;
	}

	.sort_hide{
		display:none;
	}

	table {
		border-collapse: collapse;
		width:100%;

	}

	thead {
		max-width: 1024px
	}

	td {
		padding:.2em 1em .2em .2em;
		border-bottom:1px solid grey;
		height:30px;
		font-size:12px;
		white-space: nowrap;
		font-weight: bold;
	}

	td.first {
		font-size:14px;
		white-space: normal;
	}

	td.empty {
		color:#777;
		font-style: italic;
		text-align: center;
		padding:3em 0;
	}

	.unclickable {
		pointer-events:none;
	}

	.is_dir .size {
		color:transparent;
		font-size:0;
	}

	.is_dir .size:before {
		content: "--";
		font-size:14px;
		color:#333;
	}

	.is_dir .download {
		visibility: hidden;
		color: GoldenRod;
	}

	a.delete {
		display:inline-block;
		background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAABGdBTUEAAK/INwWK6QAAABl0RVh0U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAADtSURBVHjajFC7DkFREJy9iXg0t+EHRKJDJSqRuIVaJT7AF+jR+xuNRiJyS8WlRaHWeOU+kBy7eyKhs8lkJrOzZ3OWzMAD15gxYhB+yzAm0ndez+eYMYLngdkIf2vpSYbCfsNkOx07n8kgWa1UpptNII5VR/M56Nyt6Qq33bbhQsHy6aR0WSyEyEmiCG6vR2ffB65X4HCwYC2e9CTjJGGok4/7Hcjl+ImLBWv1uCRDu3peV5eGQ2C5/P1zq4X9dGpXP+LYhmYz4HbDMQgUosWTnmQoKKf0htVKBZvtFsx6S9bm48ktaV3EXwd/CzAAVjt+gHT5me0AAAAASUVORK5CYII=) no-repeat scroll 0 2px;
		color:#d00;
		margin-left: 15px;
		font-size:11px;
		padding:0 0 0 13px;
		color: GoldenRod;
	}

	.name {
		/* background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAACXBIWXMAAA7EAAAOxAGVKw4bAAABFklEQVQ4jZXTPUoEQRCG4WeGxUg8gBjJYrSIdxAvYGAo4gE8gmAgi4iBiLmYGhiIgbggYmSmkZipLCYGYiTiTxnsLI7N7Kw2NDRUvR/VVV9lkhOMYxGzmMQHHnGK/YxuyvTBPFgNXoMYcN+C9aCRwo3goAZM71EwUhZoJwnvfxDZ7sPNCuAimA/uawQ+g5ZgqyJ4XoiPBps1Fe0KrisCZ0mPWkVVad6t4GWYQGlKy8FTKe81r5xpxcn4wpXEBznuhsHBWNH1S8yUQt0cnQomL0DBAm6wIjUQHcHUgDE2g5MhY5zul7iRBJ+HWDqCnfIfG8HhP6x8/MvKJZG16C1M3TK1o9SLrKLjE1jCnN6bn3Xey3go538DGkAuGZ0eLmUAAAAASUVORK5CYII=) no-repeat scroll 8px 15px; */
		/* background: url(../Resources/VoxCasterPublicae/play_red.png) no-repeat; */
		background-position: 8px 15px;
		background-size: 20px 20px;
		padding: 15px 0 10px 40px;
		color: GoldenRod;
		font-weight: bold;
	}

	.is_playing {
		background: url(../Resources/VoxCasterPublicae/play_green.png) no-repeat;
		background-position: 8px 15px;
		background-size: 20px 20px;
		padding:15px 0 10px 40px;
		color: GoldenRod;
		font-weight: bold;
	}

	.is_not_playing {
		background: url(../Resources/VoxCasterPublicae/play_red.png) no-repeat;
		background-position: 8px 15px;
		background-size: 20px 20px;
		padding: 15px 0 10px 40px;
		color: GoldenRod;
		font-weight: bold;
	}

	.is_dir {
		background: url(../Resources/VoxCasterPublicae/folder.png) no-repeat;
		background-position: 5px 10px;
		background-size: 27px 27px;
		color: GoldenRod;
		font-weight: bold;
	}

	.playlist {
		background: url(../Resources/VoxCasterPublicae/playlist.png) no-repeat;
		background-position: 8px 15px;
		background-size: 20px 20px;
		padding:15px 0 10px 40px;
		color: GoldenRod;
		font-weight: bold;
	}

	#breadcrumb_playlist_icon {
		background: url(../Resources/VoxCasterPublicae/playlist.png) no-repeat;
		background-position: 8px 15px;
		background-size: 20px 20px;
		padding:15px 0 10px 40px;
		color: GoldenRod;
		font-weight: bold;
	}

	.download {
		background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAB2klEQVR4nJ2ST2sTQRiHn5mdmj92t9XmUJIWJGq9NHrRgxQiCtqbl97FqxgaL34CP0FD8Qv07EHEU0Ew6EXEk6ci8Q9JtcXEkHR3k+zujIdUqMkmiANzmJdnHn7vzCuIWbe291tSkvhz1pr+q1L2bBwrRgvFrcZKKinfP9zI2EoKmm7Azstf3V7fXK2Wc3ujvIqzAhglwRJoS2ImQZMEBjgyoDS4hv8QGHA1WICvp9yelsA7ITBTIkwWhGBZ0Iv+MUF+c/cB8PTHt08snb+AGAACZDj8qIN6bSe/uWsBb2qV24/GBLn8yl0plY9AJ9NKeL5ICyEIQkkiZenF5XwBDAZzWItLIIR6LGfk26VVxzltJ2gFw2a0FmQLZ+bcbo/DPbcd+PrDyRb+GqRipbGlZtX92UvzjmUpEGC0JgpC3M9dL+qGz16XsvcmCgCK2/vPtTNzJ1x2kkZIRBSivh8Z2Q4+VkvZy6O8HHvWyGyITvA1qndNpxfguQNkc2CIzM0xNk5QLedCEZm1VKsf2XrAXMNrA2vVcq4ZJ4DhvCSAeSALXASuLBTW129U6oPrT969AK4Bq0AeWARs4BRgieMUEkgDmeO9ANipzDnH//nFB0KgAxwATaAFeID5DQNatLGdaXOWAAAAAElFTkSuQmCC) no-repeat scroll 0px 5px;
		padding:4px 0 4px 20px;
		color: GoldenRod;
		font-weight: bold;
	}

	#skull {
		pointer-events:none;
		position: absolute;
		font-size: 8px;
		color: #0e8505;

		left: 50%;
		padding-left: 24px;
		top: 24px;
	}

	.glow_green {
		-webkit-animation: glow_green 1.5s ease-in-out infinite alternate;
		-moz-animation: glow_green 1.5s ease-in-out infinite alternate;
		animation: glow_green 1.5s ease-in-out infinite alternate;
	}

	@-webkit-keyframes glow_green {
		from {
			text-shadow: 0 0 0 #fff, 0 0 10px #fff, 0 0 20px #fff, 0 0 30px #fff, 0 0 40px #fff, 0 0 50px #fff, 0 0 60px #fff, 0 0 70px #fff, 0 0 90px #fff;
		}
		to {
			text-shadow: 0 0 0 #f5f5f5, 0 0 10px #f5f5f5,0 0 20px #f5f5f5, 0 0 30px #f5f5f5, 0 0 40px #f5f5f5, 0 0 50px #f5f5f5, 0 0 60px #f5f5f5, 0 0 70px #f5f5f5, 0 0 90px #f5f5f5;
		}
	}

	#cog {
		pointer-events:none;
		position: absolute;
		top: 13px;
		right: 168px;
		font-size: 45px;
		color: #05fa67;
		text-align: center;
	}

	.glow {
		-webkit-animation: glow 1.5s ease-in-out infinite alternate;
		-moz-animation: glow 1.5s ease-in-out infinite alternate;
		animation: glow 1.5s ease-in-out infinite alternate;
	}

	@-webkit-keyframes glow {
		from {
			text-shadow: 0 0 0 #ff1414, 0 0 10px #ff1414, 0 0 20px #ff1414, 0 0 30px #ff1414, 0 0 40px #ff1414, 0 0 50px #ff1414, 0 0 60px #ff1414, 0 0 70px #ff1414, 0 0 90px #ff1414;
		}
		to {
			text-shadow: 0 0 0 #7d0909, 0 0 10px #7d0909,0 0 20px #7d0909, 0 0 30px #7d0909, 0 0 40px #7d0909, 0 0 50px #7d0909, 0 0 60px #7d0909, 0 0 70px #7d0909, 0 0 90px #7d0909;
		}
	}

	/* Reactivitude */
	@media only screen and (max-width: 720px) {
		#data_display {
			display: none;
		}
	}


</style>

<script src="../Resources/VoxCasterPublicae/jquery-3.5.1.min.js"></script>
<script src="../Resources/VoxCasterPublicae/libmidi/midi.js"></script>

<script>

function formatTime(seconds) {
		return [
				parseInt(seconds / 60 % 60),
				parseInt(seconds % 60)
		]
				.join(":")
				.replace(/\b(\d)\b/g, "0$1")
}

function formatTimestamp(unix_timestamp) {
	var m = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
	var d = new Date(unix_timestamp*1000);
	return [m[d.getMonth()],' ',d.getDate(),', ',d.getFullYear()," ",
	(d.getHours() % 12 || 12),":",(d.getMinutes() < 10 ? '0' : '')+d.getMinutes(),
	" ",d.getHours() >= 12 ? 'PM' : 'AM'].join('');
}

function formatFileSize(bytes) {
	var s = ['bytes', 'KB','MB','GB','TB','PB','EB'];
	for(var pos = 0;bytes >= 1000; pos++,bytes /= 1024);
	var d = Math.round(bytes*10);
	return pos ? [parseInt(d/10),".",d%10," ",s[pos]].join('') : bytes + ' bytes';
}

function parse_playlist(playlist) {
	playlist_path = './' + playlist.replace(/%2F/g, '/');

	var req = new XMLHttpRequest();
	req.open("GET", playlist_path, false);
	req.send();

	var playlist = req.responseText.split('\n');
	var playlist_name = playlist_path.replace(/.*\//, '');

		var file_list = [];

		for(i = 0; i < (playlist.length); i++) {
			var filepath = '.' + playlist[i].split("https://malekith.fr/VoxCasterPublicae").pop();
			if (filepath != '.') file_list.push(filepath);
		}

		return file_list;
	}

	$(function(){
		var XSRF = (document.cookie.match('(^|; )_sfm_xsrf=([^;]*)')||0)[2];
		var $tbody = $('#list');
		$(window).on('hashchange',list).trigger('hashchange');
		// $('#table').tablesorter();

		$('#table').on('click','.delete',function(data) {
			$.post("",{'do':'delete',file:$(this).attr('data-file'),xsrf:XSRF},function(response){
				list();
			},'json');
			return false;
		});

		function get_duration_from_data(data, i) {
			var row = document.getElementById("duration_row_" + i);

			var formated_data = data.split("Duration:").pop().split("\n")[0].split(",")[0].split('.')[0].replace(/:/g, ' : ');
			if(formated_data.substring(1, 5) == '00 :') formated_data = formated_data.replace('00 :', '  ');
			// row.setAttribute('data-sort', formated_data);
			row.innerHTML = String(formated_data);
		}

		function set_duration(i) {
			var hashval = window.location.hash.substr(1);
			var row = document.getElementById("duration_row_" + i);
			var filepath = row.getAttribute("data-sort");

			if(filepath.split('.')[2]) {
				if(filepath.split('.')[2] == 'm3u') {
					//TODO if file = playlist
				}
				else if (filepath.split('.')[2] == 'mid') {
					libMIDI.get_duration(filepath, function(seconds) { row.innerHTML = formatTime(seconds.toFixed(0)).replace(":", " : ");} );
				} else {
					$.get("index.php?get_audio_technical_data&track=" + filepath.replace(/&/g, '%26').replace(/ /g, '%20'), function(data) { get_duration_from_data(data, i) });
				}
			}
		}

		function init_src() {
			var hashval = window.location.hash.substr(1);
			var source = document.getElementById('audio_source');
			var src = "init";

			var file_path = decodeURIComponent(source.src);
			var req = new XMLHttpRequest();

			// dans une playlist
			if (hashval.split('.').pop() == 'm3u') {
					var playlist_path = './' + decodeURIComponent(hashval);
					req.open("GET", playlist_path, false);
					req.send();
					var playlist = req.responseText.split('\n');
					src = playlist[0];
			}

				// dans un dossier
			else {
					req.open("GET", 'playlist.m3u', false);
					req.send();
					var playlist = req.responseText.split('\n');
					var playlist = req.responseText.split('\n');
					src = playlist[0];
			}

			return src;
		}

		function list() {
			var hashval = window.location.hash.substr(1);

			document.getElementById('audio_source').src = init_src();

			$tbody.empty();
			$('#breadcrumb').empty().html(renderBreadcrumbs(hashval));

			if(hashval.split('.').pop() == 'm3u') {
				var playlist = parse_playlist(hashval);
				$('#breadcrumb_div').append('<a id="breadcrumb_playlist_icon">')
				for(i = 0; i < playlist.length; i++) {
					$.get('?do=list&file='+ playlist[i], function(data) {
						if(data.success) {
							// TODO changer la forme du path en adresse web
							var index_of_source_in_playlist = playlist.indexOf('./' + data.results[0].path);
							$tbody.append(renderFileRow(data.results[0], index_of_source_in_playlist));
							set_duration(index_of_source_in_playlist);
						} else {
							console.warn(data.error.msg);
						}
						// $('#table').retablesort();
					},'json');
				}
			} else {
				$.get('?do=list&file='+ hashval, function(data) {
					if(data.success) {
						var i = 0;
						$.each(data.results,function(k,v){
							$tbody.append(renderFileRow(v,i));
							set_duration(i);
							i++;
						});
						!data.results.length && $tbody.append('<tr><td class="empty" colspan=6>This folder is empty</td></tr>')
						data.is_writable ? $('body').removeClass('no_write') : $('body').addClass('no_write');
					} else {
						console.warn(data.error.msg);
					}
				},'json');
			}
		}

		function renderFileRow(data,i) {
			var $link = $('<a class="name" />')
			.attr('data-value', data.is_dir ? '#' : './' + data.path)
			.text(data.name);

			if (data.is_dir) $link.addClass("is_dir");
			if (data.is_dir) $link.attr('href', '#' + encodeURIComponent(data.path));
			if (data.is_dir) $link.attr('data-type', 'folder');
			if (!data.is_dir) $link.attr('data-type', data.path.split('.').pop());
			if (!data.is_dir && ($link.attr('data-type') != 'm3u')) $link.attr('art', "index.php?get_album_art&track=" + "./" + data.path);
			if (!data.is_dir && ($link.attr('data-type') != 'm3u')) $link.attr('onclick', "play(this)");
			if ($link.attr('data-type') == 'm3u') $link.attr('href', '#' +  encodeURIComponent(data.path));
			if ($link.attr('data-type') == 'm3u') $link.text(data.name.replace('.m3u', ""));
			if ($link.attr('data-type') == 'm3u') $link.addClass("playlist");

			if (!data.is_dir) {
				if("https://malekith.fr/VoxCasterPublicae/" + data.path == document.getElementById('audio_source').src) {
					$link.addClass("is_playing");
				} else {
					$link.addClass("is_not_playing");
				}
			}

			var allow_direct_link = <?php echo $allow_direct_link?'true':'false'; ?>;

			if (!data.is_dir && !allow_direct_link)  $link.css('pointer-events','none');

			var $dl_link = $('<a/>').attr('href','?do=download&file='+ encodeURIComponent(data.path))
			.addClass('download').text('Download');
			var $delete_link = $('<a href="#" />').attr('data-file',data.path).addClass('delete').text('delete');
			var perms = [];

			if(data.is_readable) perms.push('read');
			if(data.is_writable) perms.push('write');
			if(data.is_executable) perms.push('exec');

			var $html = $('<tr />')
			.append( $('<td class="first" />').append($link) )
			.append( $('<td id=duration_row_' + i + ' />').attr('data-sort', './' + data.path) )
			.append( $('<td/>').attr('data-sort',data.is_dir ? -1 : data.size)
			.html($('<span class="size" />').text(formatFileSize(data.size))) )
			.append( $('<td/>').attr('data-sort',data.mtime).text(formatTimestamp(data.mtime)) )
			.append( $('<td/>').text(perms.join('+')) )
			.append( $('<td/>').append(!data.is_dir ? $dl_link : '').append( data.is_deleteable ? $delete_link : '') )
			return $html;
		}

		function renderBreadcrumbs(path) {
			var base = "",
			$html = $('<div/ id="breadcrumb_div">').append( $('<a href=#><img class="aquila" src="../Resources/VoxCasterPublicae/aquila.png"></a></div>') );
			$.each(path.split('%2F'),function(k,v){
				if(v) {
					var v_as_text = decodeURIComponent(v);
					$html.append( $('<span/>').text(' ▸ ') )
					.append( $('<a/>').attr('href','#'+base+v).text(v_as_text.replace('.m3u', "")) );
					base += v + '%2F';
				}
			});
			return $html;
		}

	})

	String.prototype.replaceAll = function(str1, str2, ignore)
	{
		return this.replace(new RegExp(str1.replace(/([\/\,\!\\\^\$\{\}\[\]\(\)\.\*\+\?\|\<\>\-\&])/g,"\\$&"),(ignore?"gi":"g")),(typeof(str2)=="string")?str2.replace(/\$/g,"$$$$"):str2);
	}

	function append_text(string_to_append, text_area) {
		var child = document.createElement('div');
		child.innerHTML = string_to_append;
		child = child.firstChild;
		document.getElementById(text_area).appendChild(child);
	}

	function display_time(ev) {
		var midi_player_time = document.getElementById('midi_player_time');
		var bar = document.getElementById('bar');
		var duration = formatTime(midi_player_time.duration);
		var last_time = 0;

		if(ev.time <= parseFloat(midi_player_time.duration)) {
			var time = formatTime(ev.time.toFixed(0)) || 0.0;

			midi_player_time.innerHTML = time + '<a style="color:grey;"> / ' + duration + '</a>';
			last_time = ev.time;

			var bar_width = String(ev.time / midi_player_time.duration * 100) + '%';
			bar.style.width = bar_width;
			if(time == duration) bar.setAttribute("ended", "true");

		} else if (bar.getAttribute("ended") == "true") {
			midi_player_time.innerHTML = duration + '<a style="color:grey;"> / ' + duration + '</a>';
			document.getElementById('midi_pause').style.visibility = 'hidden';
			document.getElementById('midi_play').style.visibility = 'visible';

		} else {
			midi_player_time.innerHTML = '00:00<a style="color:grey;"> / 00:00</a>';
		}
	}

	function is_playing_change_state() {
		var is_playing = document.querySelectorAll('.is_playing');
		for(i = 0; i < is_playing.length; i++) {
			is_playing[i].classList.add('is_not_playing');
			is_playing[i].classList.remove('is_playing');
		}
	}

	function parse_audio_metadata(data) {
		var text_data = document.getElementById('audio_data_1');
		// regex dodgin' shenanigans
		var formated_data = '<u>METADATAS</u><br>' + data.replace(';FFMETADATA1\n', '<br /><br />').split("=").join(' : ').split('\n').join("<br /> <br />").slice(0, -1) + '<br><br><br>';
		text_data.innerHTML = formated_data;
		text_data.style.visibility = 'visible';
	}

	function parse_audio_technical_data(data) {
		var text_data = document.getElementById('audio_data_2');
		// regex dodgin' shenanigans
		var formated_data = '<u>TECHNICAL DATAS</u><br /><br /><br />  Duration : ' + data.split('\n').join("<br /> <br />").split(',').join("<br />").split("Duration:").pop().split('At')[0].slice(0, -1);
		text_data.innerHTML = formated_data;
		text_data.style.visibility = 'visible';
	}

	function get_audio_metadata() {
		var source = document.getElementById('audio_source');
		var filepath = '.' + source.src.split("https://malekith.fr/VoxCasterPublicae").pop();

		$.get("index.php?get_formated_audio_metadata&track=" + filepath.replace(/&/g, '%26').replace(/ /g, '%20'), parse_audio_metadata);
	}

	function get_audio_technical_data() {
		var source = document.getElementById('audio_source');
		var filepath = '.' + source.src.split("https://malekith.fr/VoxCasterPublicae").pop();

		$.get("index.php?get_audio_technical_data&track=" + filepath.replace(/&/g, '%26').replace(/ /g, '%20'), parse_audio_technical_data);
	}

	function get_true_link() {
		var text_data = document.getElementById('audio_data_3');
		var source = document.getElementById('audio_source').src;

		text_data.innerHTML = '<u>TRUE LINK </u><br /><br /><br />' + decodeURIComponent(source)  + '<br><br>';
		text_data.style.visibility = 'visible';
	}

	function parse_album_art(data) {
		var album_art = document.getElementById('album_art');
		if(data == 'null') {
			album_art.style.visibility = 'hidden';
		} else {
			album_art.style.visibility = 'visible';
		}
	}

	function check_album_art() {
		var source = document.getElementById('audio_source');
		var filepath = '.' + source.src.split("https://malekith.fr/VoxCasterPublicae").pop();

		$.get("index.php?get_album_art&track=" + filepath, parse_album_art);
	}

	function get_list_playables_in_dir(dir, playlist) {
		var playables = [];

		for (i = 0; i < playlist.length - 1; i++) {
			if (String(playlist[i].split("https://malekith.fr/VoxCasterPublicae/").pop().match(/.*\//)) == String(dir)) {
				playables.push(playlist[i]);
			}
		}

		return playables
	}

	// play next song
	function play_next(override = false) {
		var source = document.getElementById('audio_source');
		if(source.src == "https://malekith.fr/VoxCasterPublicae/init") return;
		if(source.src == "init") return;

		var autoplay = document.getElementById('is_autoplay').checked;
		var loop = document.getElementById('is_loop').checked;
		var random = document.getElementById('is_random').checked;

		document.getElementById("speed_data").innerHTML = document.getElementById("audio_player").playbackRate;

		if(override || autoplay) {
			var hashval = window.location.hash.substr(1);
			var album_art = document.getElementById('album_art');
			var text_field = document.getElementById('audio_info');
			var player = document.getElementById('audio_player');
			var text_data_1 = document.getElementById('audio_data_1');
			var text_data_2 = document.getElementById('audio_data_2');
			var cog = document.getElementById('cog');

			cog.classList.remove("glow");
			album_art.style.visibility = 'hidden';

			text_data_1.style.visibility = 'hidden';
			text_data_2.style.visibility = 'hidden';

			var file_path = decodeURIComponent(source.src);
			var req = new XMLHttpRequest();

			// IN PLAYLIST
			if (hashval.split('.').pop() == 'm3u') {
				var playlist_path = './' + decodeURIComponent(hashval);
				req.open("GET", playlist_path, false);
				req.send();

				var playlist = req.responseText.split('\n');
				var index_of_source_in_playlist = playlist.indexOf(file_path);

				// random in playlist
				if (random) {
					var playables = playlist;

					var randomly_picked_track = playables[Math.floor(Math.random()*playables.length - 1)];
					source.src = randomly_picked_track;

					var filename = source.src.split("https://malekith.fr/VoxCasterPublicae").pop();
					filename = "Home" + decodeURIComponent(filename).replaceAll('/', " \u25B8 ");
					text_field.value = filename;

					// set the correct icon
					is_playing_change_state();

					var next_playing = document.querySelectorAll('.is_not_playing');
					for(i = 0; i < next_playing.length; i++) {
						if(next_playing[i].getAttribute('data-type') != 'folder') {
							if(next_playing[i].getAttribute('data-type') != 'm3u') {
								if(("https://malekith.fr/VoxCasterPublicae/" + next_playing[i].getAttribute('data-value').split("./").pop()) == randomly_picked_track) {
									next_playing[i].classList.add('is_playing');
									next_playing[i].classList.remove('is_not_playing');

									var art_src = next_playing[i].getAttribute("art");
									album_art.setAttribute("src", art_src);
									check_album_art();
								}
							}
						}
					}

					// pause the former song and load the next one
					player.pause();

					if(source.src.split('.').pop() == 'mid') {
						player.style.visibility = 'hidden';

						document.getElementById('midi_player').style.visibility = 'visible';

						document.getElementById('bar').setAttribute("ended", "false");

						libMIDI.player_callback = display_time;

						// on stock la durée dans un attribut comme un gros sauvage
						document.getElementById('midi_player_time').setAttribute("duration", "");
						libMIDI.get_duration(source.src, function(seconds) { document.getElementById('midi_player_time').duration = seconds.toFixed(3);} );

						document.getElementById('midi_play').style.visibility = 'hidden';
						document.getElementById('midi_pause').style.visibility = 'visible';

						libMIDI.play(source.src);

					} else {
						midi_stop()
						player.load();
						player.play();

						get_audio_metadata();
						get_audio_technical_data();
					}

					cog.classList.add("glow");
					get_true_link();

					return;
				}

				// song to play :
				if((index_of_source_in_playlist + 1) < playlist.length - 1) {
					source.src = playlist[index_of_source_in_playlist + 1];
					var filename = decodeURIComponent(source.src.split("https://malekith.fr/VoxCasterPublicae").pop());
					filename = "Home" + decodeURIComponent(filename).replaceAll('/', " \u25B8 ");
					text_field.value = filename;

					// set the correct icon
					is_playing_change_state();

					var next_playing = document.querySelectorAll(".is_not_playing");
					for(i = 0; i < next_playing.length; i++) {
						if(next_playing[i].getAttribute('data-type') != 'folder') {
							if(next_playing[i].getAttribute('data-type') != 'm3u') {
								if(("https://malekith.fr/VoxCasterPublicae/" + next_playing[i].getAttribute('data-value').split("./").pop()) == (playlist[index_of_source_in_playlist + 1])) {
									next_playing[i].classList.add('is_playing');
									next_playing[i].classList.remove('is_not_playing');

									var art_src = next_playing[i].getAttribute("art");
									album_art.setAttribute("src", art_src);
									check_album_art();
								}
							}
						}
					}
					// pause the former song and load the next one
					player.pause();

					if(source.src.split('.').pop() == 'mid') {
						player.style.visibility = 'hidden';

						document.getElementById('midi_player').style.visibility = 'visible';

						document.getElementById('bar').setAttribute("ended", "false");

						libMIDI.player_callback = display_time;

						// on stock la durée dans un attribut comme un gros sauvage
						document.getElementById('midi_player_time').setAttribute("duration", "");
						libMIDI.get_duration(source.src, function(seconds) { document.getElementById('midi_player_time').duration = seconds.toFixed(3);} );

						document.getElementById('midi_play').style.visibility = 'hidden';
						document.getElementById('midi_pause').style.visibility = 'visible';

						libMIDI.play(source.src);

					} else {
						midi_stop()
						player.load();
						player.play();

						get_audio_metadata();
						get_audio_technical_data();
					}

					cog.classList.add("glow");
					get_true_link();
				}
				// loop back
				else if ((loop && autoplay) || override) {

					source.src = playlist[0];
					var filename = source.src.split("https://malekith.fr/VoxCasterPublicae").pop();
					filename = "Home" + decodeURIComponent(filename).replaceAll('/', " \u25B8 ");
					text_field.value = filename;

					// set the correct icon
					is_playing_change_state();

					var next_playing = document.querySelectorAll('.is_not_playing');
					for(i = 0; i < next_playing.length; i++) {
						if(next_playing[i].getAttribute('data-type') != 'folder') {
							if(next_playing[i].getAttribute('data-type') != 'm3u') {
								if(("https://malekith.fr/VoxCasterPublicae/" + next_playing[i].getAttribute('data-value').split("./").pop()) == (playlist[0])) {
									next_playing[i].classList.add('is_playing');
									next_playing[i].classList.remove('is_not_playing');

									var art_src = next_playing[i].getAttribute("art");
									album_art.setAttribute("src", art_src);
									check_album_art();
								}
							}
						}
					}

					// pause the former song and load the next one
					player.pause();

					if(source.src.split('.').pop() == 'mid') {
						player.style.visibility = 'hidden';

						document.getElementById('midi_player').style.visibility = 'visible';

						document.getElementById('bar').setAttribute("ended", "false");

						libMIDI.player_callback = display_time;

						// on stock la durée dans un attribut comme un gros sauvage
						document.getElementById('midi_player_time').setAttribute("duration", "");
						libMIDI.get_duration(source.src, function(seconds) { document.getElementById('midi_player_time').duration = seconds.toFixed(3);} );

						document.getElementById('midi_play').style.visibility = 'hidden';
						document.getElementById('midi_pause').style.visibility = 'visible';

						libMIDI.play(source.src);

					} else {
						midi_stop()
						player.load();
						player.play();

						get_audio_metadata();
						get_audio_technical_data();
					}

					cog.classList.add("glow");
					get_true_link();

				} else {
					player.pause();
					get_audio_metadata();
					get_audio_technical_data();
					get_true_link();
				}

			// NOT IN PLAYLIST
			} else {
				// ./playlist.m3u holds the list of songs to play
				req.open("GET", 'playlist.m3u', false);
				req.send();

				var playlist = req.responseText.split('\n');
				var filepath = decodeURIComponent(source.src.split("./").pop());
				var file_dir_location = filepath.split("https://malekith.fr/VoxCasterPublicae/").pop().match(/.*\//);
				var playlist = get_list_playables_in_dir(file_dir_location, playlist);
				var index_of_source_in_playlist = playlist.indexOf(filepath) ;
				var first_dir_index = index_of_source_in_playlist;

					if (first_dir_index > 0) {
						for (i = first_dir_index - 1; i >= 0; i--) {
							if (String(playlist[i].split("https://malekith.fr/VoxCasterPublicae/").pop().match(/.*\//)) == String(file_dir_location)) {
								first_dir_index = i;
							}
						}
					}

					// random not in playlist
					if (random) {

						var randomly_picked_track = playlist[Math.floor(Math.random()*playlist.length)];
						source.src = randomly_picked_track;
						document.getElementById('audio_data_1').innerHTML = playlist;

						var filename = source.src.split("https://malekith.fr/VoxCasterPublicae").pop();
						filename = "Home" + decodeURIComponent(filename).replaceAll('/', " \u25B8 ");
						text_field.value = filename;

						// set the correct icon
						is_playing_change_state();

						var next_playing = document.querySelectorAll('.is_not_playing');
						for(i = 0; i < next_playing.length; i++) {
							if(next_playing[i].getAttribute('data-type') != 'folder') {
								if(next_playing[i].getAttribute('data-type') != 'm3u') {
									if(("https://malekith.fr/VoxCasterPublicae/" + next_playing[i].getAttribute('data-value').split("./").pop()) == randomly_picked_track) {
										next_playing[i].classList.add('is_playing');
										next_playing[i].classList.remove('is_not_playing');

										var art_src = next_playing[i].getAttribute("art");
										album_art.setAttribute("src", art_src);
										check_album_art();
									}
								}
							}
						}

						// pause the former song and load the next one
						player.pause();

						if(source.src.split('.').pop() == 'mid') {
							player.style.visibility = 'hidden';

							document.getElementById('midi_player').style.visibility = 'visible';

							document.getElementById('bar').setAttribute("ended", "false");

							libMIDI.player_callback = display_time;

							// on stock la durée dans un attribut comme un gros sauvage
							document.getElementById('midi_player_time').setAttribute("duration", "");
							libMIDI.get_duration(source.src, function(seconds) { document.getElementById('midi_player_time').duration = seconds.toFixed(3);} );

							document.getElementById('midi_play').style.visibility = 'hidden';
							document.getElementById('midi_pause').style.visibility = 'visible';

							libMIDI.play(source.src);

						} else {
							midi_stop()
							player.load();
							player.play();

							get_audio_metadata();
							get_audio_technical_data();
						}

						cog.classList.add("glow");
						get_true_link();

						return;
					}


					// si le fichier reference n'est pas au bout
					if ((index_of_source_in_playlist + 1) < playlist.length) {
						if (String(playlist[index_of_source_in_playlist + 1].split("https://malekith.fr/VoxCasterPublicae/").pop().match(/.*\//)) == String(file_dir_location)) {
							source.src = playlist[index_of_source_in_playlist + 1];
							var filename = source.src.split("https://malekith.fr/VoxCasterPublicae").pop();
							filename = "Home" + filename.replaceAll('/', " \u25B8 ").replace(/%20/g, ' ');
							text_field.value = filename;

							// set the correct icon
							is_playing_change_state();

							var next_playing = document.querySelectorAll(".is_not_playing");
							for(i = 0; i < next_playing.length; i++) {
								if(next_playing[i].getAttribute('data-type') != 'folder') {
									if(next_playing[i].getAttribute('data-type') != 'm3u') {
										if(("https://malekith.fr/VoxCasterPublicae/" + next_playing[i].getAttribute('data-value').split("./").pop()) == (playlist[index_of_source_in_playlist + 1])) {
											next_playing[i].classList.add('is_playing');
											next_playing[i].classList.remove('is_not_playing');

											var art_src = next_playing[i].getAttribute("art");
											album_art.setAttribute("src", art_src);
											check_album_art();
										}
									}
								}
							}
							// pause the former song and load the next one
							player.pause();

							if(source.src.split('.').pop() == 'mid') {
								player.style.visibility = 'hidden';

								document.getElementById('midi_player').style.visibility = 'visible';

								document.getElementById('bar').setAttribute("ended", "false");

								libMIDI.player_callback = display_time;

								// on stock la durée dans un attribut comme un gros sauvage
								document.getElementById('midi_player_time').setAttribute("duration", "");
								libMIDI.get_duration(source.src, function(seconds) { document.getElementById('midi_player_time').duration = seconds.toFixed(3);} );

								document.getElementById('midi_play').style.visibility = 'hidden';
								document.getElementById('midi_pause').style.visibility = 'visible';

								libMIDI.play(source.src);

							} else {
								midi_stop()
								player.load();
								player.play();

								get_audio_metadata();
								get_audio_technical_data();
							}

							cog.classList.add("glow");
							get_true_link();
						}
						// si la fin du fichier reference
						// loop back
						else if ((loop && autoplay) || override) {
							source.src = playlist[first_dir_index];
							var filename = source.src.split("https://malekith.fr/VoxCasterPublicae").pop();
							filename = "Home" + filename.replaceAll('/', " \u25B8 ").replace(/%20/g, ' ');
							text_field.value = filename;

							// set the correct icon
							is_playing_change_state();

							var next_playing = document.querySelectorAll('.is_not_playing');
							for(i = 0; i < next_playing.length; i++) {
								if(next_playing[i].getAttribute('data-type') != 'folder') {
									if(next_playing[i].getAttribute('data-type') != 'm3u') {
										if(("https://malekith.fr/VoxCasterPublicae/" + next_playing[i].getAttribute('data-value').split("./").pop()) == (playlist[first_dir_index])) {
											next_playing[i].classList.add('is_playing');
											next_playing[i].classList.remove('is_not_playing');

											var art_src = next_playing[i].getAttribute("art");
											album_art.setAttribute("src", art_src);
											check_album_art();
										}
									}
								}
							}

							// pause the former song and load the next one
							player.pause();

							if(source.src.split('.').pop() == 'mid') {
								player.style.visibility = 'hidden';

								document.getElementById('midi_player').style.visibility = 'visible';

								document.getElementById('bar').setAttribute("ended", "false");

								libMIDI.player_callback = display_time;

								// on stock la durée dans un attribut comme un gros sauvage
								document.getElementById('midi_player_time').setAttribute("duration", "");
								libMIDI.get_duration(source.src, function(seconds) { document.getElementById('midi_player_time').duration = seconds.toFixed(3);} );

								document.getElementById('midi_play').style.visibility = 'hidden';
								document.getElementById('midi_pause').style.visibility = 'visible';

								libMIDI.play(source.src);

							} else {
								midi_stop()
								player.load();
								player.play();

								get_audio_metadata();
								get_audio_technical_data();
							}

							cog.classList.add("glow");
							get_true_link();

						} else {
							player.pause();
							get_audio_metadata();
							get_audio_technical_data();
							get_true_link();
						}
					}
					// loop back
					else if ((loop && autoplay) || override) {
						source.src = playlist[first_dir_index];
						var filename = source.src.split("https://malekith.fr/VoxCasterPublicae").pop();
						filename = "Home" + filename.replaceAll('/', " \u25B8 ").replace(/%20/g, ' ');
						text_field.value = filename;

						// set the correct icon
						is_playing_change_state();

						var next_playing = document.querySelectorAll('.is_not_playing');
						for(i = 0; i < next_playing.length; i++) {
							if(next_playing[i].getAttribute('data-type') != 'folder') {
								if(next_playing[i].getAttribute('data-type') != 'm3u') {
									if(("https://malekith.fr/VoxCasterPublicae/" + next_playing[i].getAttribute('data-value').split("./").pop()) == (playlist[first_dir_index])) {
										next_playing[i].classList.add('is_playing');
										next_playing[i].classList.remove('is_not_playing');

										var art_src = next_playing[i].getAttribute("art");
										album_art.setAttribute("src", art_src);
										check_album_art();
									}
								}
							}
						}

						// pause the former song and load the next one
						player.pause();

						if(source.src.split('.').pop() == 'mid') {
							player.style.visibility = 'hidden';

							document.getElementById('midi_player').style.visibility = 'visible';

							document.getElementById('bar').setAttribute("ended", "false");

							libMIDI.player_callback = display_time;

							// on stock la durée dans un attribut comme un gros sauvage
							document.getElementById('midi_player_time').setAttribute("duration", "");
							libMIDI.get_duration(source.src, function(seconds) { document.getElementById('midi_player_time').duration = seconds.toFixed(3);} );

							document.getElementById('midi_play').style.visibility = 'hidden';
							document.getElementById('midi_pause').style.visibility = 'visible';

							libMIDI.play(source.src);

						} else {
							midi_stop()
							player.load();
							player.play();

							get_audio_metadata();
							get_audio_technical_data();
						}

						cog.classList.add("glow");
						get_true_link();
					}
				}
		}

		}


		// play music on click
		function play(e) {

			var album_art = document.getElementById('album_art');
			var player = document.getElementById('audio_player');
			var source = document.getElementById('audio_source');
			var text_field = document.getElementById('audio_info');
			var text_data_1 = document.getElementById('audio_data_1');
			var text_data_2 = document.getElementById('audio_data_2');
			var text_data_3 = document.getElementById('audio_data_3');
			var midi_player_time = document.getElementById('midi_player_time');
			var cog = document.getElementById('cog');

			var date_type = e.getAttribute('data-type');
			var file_path = decodeURIComponent(e.getAttribute('data-value'));

			document.getElementById("speed_data").innerHTML = document.getElementById("audio_player").playbackRate;

			if (e.classList.contains('is_playing')) {
				if(date_type == "mid") {

					if(document.getElementById('bar').getAttribute("ended") == 'true') {
						document.getElementById('bar').setAttribute("ended", "false");

						player.pause();
						libMIDI.player_callback = display_time;

						// on stock la durée dans un attribut comme un gros sauvage
						midi_player_time.setAttribute("duration", "");
						libMIDI.get_duration(file_path, function(seconds) { document.getElementById('midi_player_time').duration = seconds.toFixed(3);} );

						document.getElementById('midi_play').style.visibility = 'hidden';
						document.getElementById('midi_pause').style.visibility = 'visible';

						libMIDI.play(file_path);
						cog.classList.add("glow");
					} else {
						if(document.getElementById('midi_play').style.visibility == 'hidden') {
							midi_pause();
						} else {
							midi_resume();
						}
					}
				} else {
					if (player.paused) {
						player.play();
					} else {
						player.pause();
					}
				}
			} else {
				text_data_1.style.visibility = 'hidden';
				text_data_2.style.visibility = 'hidden';
				album_art.style.visibility = 'hidden';

				is_playing_change_state();
				e.classList.add('is_playing');
				e.classList.remove('is_not_playing');

				midi_stop();
				cog.classList.remove("glow");

				text_data_1.innerHTML = "";

				// format the texbox
				var filename = file_path.replace('./', "");
				filename = "Home" + " \u25B8 " + filename.replaceAll('/', " \u25B8 ");
				text_field.value = filename;

				if(date_type == "mid") {
					player.style.visibility = 'hidden';
					cog.classList.add("glow");

					document.getElementById('midi_player').style.visibility = 'visible';

					document.getElementById('bar').setAttribute("ended", "false");

					text_data_1.innerHTML = '';
					text_data_1.style.visibility = 'hidden';

					player.pause();
					libMIDI.player_callback = display_time;

					// on stock la durée dans un attribut comme un gros sauvage
					midi_player_time.setAttribute("duration", "");
					libMIDI.get_duration(file_path, function(seconds) { document.getElementById('midi_player_time').duration = seconds.toFixed(3);} );

					document.getElementById('midi_play').style.visibility = 'hidden';
					document.getElementById('midi_pause').style.visibility = 'visible';

					libMIDI.play(file_path);

					source.src = file_path;
					get_true_link();
				}

				else {
					player.style.visibility = 'visible';
					document.getElementById('midi_player').style.visibility = 'hidden';
					document.getElementById('midi_play').style.visibility = 'hidden';
					document.getElementById('midi_pause').style.visibility = 'visible';

					source.src = file_path;

					player.load(); //call this to just preload the audio without playing
					player.play(); //call this to play the song right away
					cog.classList.add("glow");

					get_audio_metadata();
					get_audio_technical_data();
					get_true_link();

					var art_src = e.getAttribute("art");
					album_art.setAttribute("src", art_src);
					check_album_art();
				}
			}
		}

		function midi_resume() {
			var file_path = document.getElementById('audio_source').src; //oui, on récupère la source du player html... Sait-on jamais si un jour le support MIDI est implémenté...
			var cog = document.getElementById('cog');
			cog.classList.add("glow");

			if(document.getElementById('bar').getAttribute("ended") == 'true') {
				document.getElementById('bar').setAttribute("ended", "false");

				document.getElementById('audio_player').pause();
				libMIDI.player_callback = display_time;

				// on stock la durée dans un attribut comme un gros sauvage
				document.getElementById('midi_player_time').setAttribute("duration", "");
				libMIDI.get_duration(file_path, function(seconds) { document.getElementById('midi_player_time').duration = seconds.toFixed(3);} );

				document.getElementById('midi_play').style.visibility = 'hidden';
				document.getElementById('midi_pause').style.visibility = 'visible';

				libMIDI.play(file_path);
				document.getElementById('cog').classList.add("glow");
			} else {
				libMIDI.resume(file_path);
			}

			document.getElementById('midi_play').style.visibility = 'hidden';
			document.getElementById('midi_pause').style.visibility = 'visible';
		}

		function midi_pause() {
			var file_path = document.getElementById('audio_source').src;
			libMIDI.pause(file_path);
			var cog = document.getElementById('cog');
			cog.classList.remove("glow");

			document.getElementById('midi_play').style.visibility = 'visible';
			document.getElementById('midi_pause').style.visibility = 'hidden';
		}

		function midi_stop() {
			var file_path = document.getElementById('audio_source').src;
			libMIDI.stop(file_path);
			var cog = document.getElementById('cog');
			cog.classList.remove("glow");

			document.getElementById('audio_player').style.visibility = 'visible';
		}

		function cog_unglow() {
			var cog = document.getElementById('cog');
			cog.classList.remove("glow");
		}

		function cog_glow() {
			var cog = document.getElementById('cog');
			cog.classList.add("glow");

			var skull = document.getElementById('skull');
			skull.classList.add("glow_green");
		}

		function midi_play_color_blue(e) {
			e.setAttribute("src", "../Resources/VoxCasterPublicae/midi_player_play.png");
		}

		function midi_play_color_white(e) {
			e.setAttribute("src", "../Resources/VoxCasterPublicae/midi_player_play_white.png");
		}

		function midi_pause_color_blue(e) {
			e.setAttribute("src", "../Resources/VoxCasterPublicae/midi_player_pause.png");
		}

		function midi_pause_color_white(e) {
			e.setAttribute("src", "../Resources/VoxCasterPublicae/midi_player_pause_white.png");
		}

		function speed_p() {
			var speed = document.getElementById("audio_player").defaultPlaybackRate + 0.25;
			document.getElementById("audio_player").defaultPlaybackRate = speed;
			document.getElementById("audio_player").playbackRate = speed;

			if (speed < 4) {
				document.getElementById("speedp").style.visibility = 'visible';
				document.getElementById("speedm").style.visibility = 'visible';
			} else {
				document.getElementById("speedp").style.visibility = 'hidden';
			}

			document.getElementById("speed_data").innerHTML = document.getElementById("audio_player").playbackRate;
		}

		function speed_m() {
			var speed = document.getElementById("audio_player").defaultPlaybackRate - 0.25;
			document.getElementById("audio_player").playbackRate = speed;
			document.getElementById("audio_player").defaultPlaybackRate = speed;

			if (speed > 0.25){
				document.getElementById("speedp").style.visibility = 'visible';
				document.getElementById("speedm").style.visibility = 'visible';
			} else {
				document.getElementById("speedm").style.visibility = 'hidden';
			}

			document.getElementById("speed_data").innerHTML = document.getElementById("audio_player").playbackRate;
		}

		function speed_n() {
			document.getElementById("audio_player").defaultPlaybackRate = 1;
			document.getElementById("audio_player").playbackRate = 1;

			document.getElementById("speed_data").innerHTML = document.getElementById("audio_player").playbackRate;

			document.getElementById("speedm").style.visibility = 'visible';
			document.getElementById("speedp").style.visibility = 'visible';
		}

		function forward() {
			var current_time = document.getElementById("audio_player").currentTime;
			var duration = document.getElementById("audio_player").duration;

			document.getElementById("audio_player").currentTime = current_time + 10;
		}

		function backward() {
			var current_time = document.getElementById("audio_player").currentTime;
			var duration = document.getElementById("audio_player").duration;

			document.getElementById("audio_player").currentTime = current_time - 10;
		}

		</script>

		<title>Vox Caster Publicae</title>

		<head>
			<link rel="icon" type="image/png" sizes="32x32" href="../Resources/VoxCasterPublicae/voxcast-32x32.png">
			<link rel="icon" type="image/png" sizes="16x16" href="../Resources/VoxCasterPublicae/voxcast-16x16.png">
		</head>

		<div id="midi_player">
			<image id="midi_play" src="../Resources/VoxCasterPublicae/midi_player_play_white.png" onclick="midi_resume()"  onmouseover="midi_play_color_blue(this)" onmouseout ="midi_play_color_white(this)"></image>
			<image id="midi_pause" src="../Resources/VoxCasterPublicae/midi_player_pause_white.png" onclick="midi_pause()"  onmouseover="midi_pause_color_blue(this)" onmouseout ="midi_pause_color_white(this)"></image>
			<div id="midi_progressbar"><div id="bar" ended="false"><span id="midi_bar_ball"></span></div></div>
			<div id="midi_player_time" >00:00<a style="color:grey;"> / 00:00</a></div>
		</div>

		<div>
		<audio id="audio_player" onended="play_next()" onpause="cog_unglow()" onplaying="cog_glow()" controls>
				<source id="audio_source"> </source>
		</audio>
		<div id="speed_data"></div>
		<span id="skull">&#9679;</span>
		<image id="speed" src="../Resources/VoxCasterPublicae/speed.png"></image>
		<textarea id="audio_info" row="1" cols="1" readonly></textarea>
	</div>


		<div id="data_display">
			<a id="audio_data">
				<div id="audio_data_3"></div>
				<div id="audio_data_1"></div>
				<div id="audio_data_2"></div>
			</a>
			<span id="cog">&#9673;</span>
			<img id="album_art">
			<img id="overlay" src="../Resources/VoxCasterPublicae/overlay.png">
		</div>

		<div id="buttons_raw">
			<image src="../Resources/VoxCasterPublicae/next.png" id="play_next" onclick="play_next(true)"></image>
			<image src="../Resources/VoxCasterPublicae/backward.png" id="backward" onclick="backward()"></image>
			<image src="../Resources/VoxCasterPublicae/forward.png" id="forward" onclick="forward()"></image>
			<image src="../Resources/VoxCasterPublicae/moins.png" id="speedm" onclick="speed_m()"></image>
			<image src="../Resources/VoxCasterPublicae/bouton.png" id="speed_normal" onclick="speed_n()"></image>
			<image src="../Resources/VoxCasterPublicae/plus.png" id="speedp" onclick="speed_p()"></image>
			<div id="checkbox_raw">
				<input type="checkbox" id="is_autoplay" name="is_autoplay" value="true">autoplay</input>
				<input type="checkbox" id="is_loop" name="is_loop" value="true">loop</input>
				<input type="checkbox" id="is_random" name="is_random" value="true">random</input>
			</div>
		</div>

		<body>
			<div id="top">
				<div id="breadcrumb">&nbsp;</div>
			</div>

			<div id="mid">
				<table id="table">
					<thead>
						<tr>
							<th class="unclickable">Name</th>
							<th class="unclickable">Duration</th>
							<th class="unclickable">Size</th>
							<th class="unclickable">Modified</th>
							<th class="unclickable">Permissions</th>
							<th class="unclickable">Actions</th>
						</tr>
					</thead>
					<tbody id="list">

					</tbody>
				</table>
			</div>
			<footer>
				<a></a>
			</footer>
		</body>
		</html>
