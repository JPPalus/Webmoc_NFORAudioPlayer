<?php
	$sfile = escapeshellarg($_GET["track"]);
	$img = shell_exec("ffmpeg -i $sfile -f image2pipe pipe:1 2>/dev/null");

	header("Content-type: image/*");
	if (strlen($img) != 0)
		echo($img);
	else // Black pixel.
		echo(base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVQIW2NgAAAAAgABYkBPaAAAAABJRU5ErkJggg=="));
?>
