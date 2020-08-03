<?php

//Disable error report for undefined superglobals
error_reporting( error_reporting() & ~E_NOTICE );

//Security options
$allow_direct_link = true; // Set to false to only allow downloads and not direct link
$allow_show_folders = true; // Set to false to hide all subdirectories

$disallowed_patterns = ['*.php'];  // must be an array.  Matching files not allowed to be uploaded
$allowed_patterns = ['*.mp3', '*.wav', '*.flac', '*.ogg']; // Matching files hidden in directory index

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
		foreach ($files as $entry) if (is_entry_allowed($entry, $allow_show_folders, $allowed_patterns)) {
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
	} else {
		err(412,"Not a Directory");
	}
	echo json_encode(['success' => true, 'is_writable' => is_writable($file), 'results' =>$result]);
	exit;
	
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

function is_entry_allowed($entry, $allow_show_folders, $allowed_patterns) {
	if ($entry === basename(__FILE__)) {
		return false;
	}

	if(fnmatch('.*', $entry)) {
		return false;
	}

	if (is_dir($entry) && $allow_show_folders) {
		return true;
	}
	foreach($allowed_patterns as $pattern) {
		if(fnmatch($pattern, $entry)) {
			return true;
		}
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

function err($code,$msg) {
	http_response_code($code);
	header("Content-Type: application/json");
	echo json_encode(['error' => ['code'=>intval($code), 'msg' => $msg]]);
	exit;
}

function asBytes($ini_v) {
	$ini_v = trim($ini_v);
	$s = ['g'=> 1<<30, 'm' => 1<<20, 'k' => 1<<10];
	return intval($ini_v) * ($s[strtolower(substr($ini_v,-1))] ?: 1);
}

$MAX_UPLOAD_SIZE = min(asBytes(ini_get('post_max_size')), asBytes(ini_get('upload_max_filesize')));
?>

<!DOCTYPE html>
<html><head>
	<meta http-equiv="content-type" content="text/html; charset=utf-8">

	<style>

	.aquila {
		position: absolute;
		top: 8px;
		right: 16px;
		padding-top: 4px;
		width: 100px;
	}


	body {
		font-family: "lucida grande",
		"Segoe UI",
		Arial,
		sans-serif;
		font-size:14px;
		color: GoldenRod;
		width:1024;
		padding:1em;
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

	thead {
		border-top: 5px solid #018a30;
		border-bottom: 5px solid #018a30;
		border-left: 5px solid #018a30;
		border-right: 5px solid #018a30;

	}

	#top {
		height:52px;
		color: GoldenRod;
	}

	#mkdir {
		display:inline-block;
		float:right;
		padding-top:16px;
	}

	label {
		display:block;
		font-size:11px;
		color:#555;
	}

	#file_drop_target {
		width:500px;
		padding:12px 0;
		border: 4px dashed #008700;
		font-size:12px;
		color:#ccc;
		text-align: center;
		float:right;
		margin-right:20px;
	}

	#file_drop_target.drag_over {
		border: 4px dashed #96C4EA;
		color: #96C4EA;
	}

	#upload_progress {
		padding: 4px 0;
	}

	#upload_progress .error {
		color:#a00;
	}

	#upload_progress > div {
		padding:3px 0;
	}

	.no_write #mkdir, .no_write #file_drop_target {
		display: none
	}

	.progress_track {
		display:inline-block;
		width:200px;
		height:10px;
		border:1px solid #333;
		margin: 0 4px 0 10px;
	}

	.progress {
		background-color: #82CFFA;
		height:10px;
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

	#breadcrumb {
		font-weight: bold;
		padding-top:34px;
		font-size:15px;
		color:red;
		display:inline-block;
		float:left;
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
		background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAACXBIWXMAAA7EAAAOxAGVKw4bAAABFklEQVQ4jZXTPUoEQRCG4WeGxUg8gBjJYrSIdxAvYGAo4gE8gmAgi4iBiLmYGhiIgbggYmSmkZipLCYGYiTiTxnsLI7N7Kw2NDRUvR/VVV9lkhOMYxGzmMQHHnGK/YxuyvTBPFgNXoMYcN+C9aCRwo3goAZM71EwUhZoJwnvfxDZ7sPNCuAimA/uawQ+g5ZgqyJ4XoiPBps1Fe0KrisCZ0mPWkVVad6t4GWYQGlKy8FTKe81r5xpxcn4wpXEBznuhsHBWNH1S8yUQt0cnQomL0DBAm6wIjUQHcHUgDE2g5MhY5zul7iRBJ+HWDqCnfIfG8HhP6x8/MvKJZG16C1M3TK1o9SLrKLjE1jCnN6bn3Xey3go538DGkAuGZ0eLmUAAAAASUVORK5CYII=) no-repeat scroll 8px 15px;
		padding:15px 0 10px 40px;
		color: GoldenRod;
		font-weight: bold;
	}

	.is_dir .name {
		background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAADdgAAA3YBfdWCzAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAI0SURBVFiF7Vctb1RRED1nZu5977VQVBEQBKZ1GCDBEwy+ISgCBsMPwOH4CUXgsKQOAxq5CaKChEBqShNK222327f79n0MgpRQ2qC2twKOGjE352TO3Jl76e44S8iZsgOww+Dhi/V3nePOsQRFv679/qsnV96ehgAeWvBged3vXi+OJewMW/Q+T8YCLr18fPnNqQq4fS0/MWlQdviwVqNpp9Mvs7l8Wn50aRH4zQIAqOruxANZAG4thKmQA8D7j5OFw/iIgLXvo6mR/B36K+LNp71vVd1cTMR8BFmwTesc88/uLQ5FKO4+k4aarbuPnq98mbdo2q70hmU0VREkEeCOtqrbMprmFqM1psoYAsg0U9EBtB0YozUWzWpVZQgBxMm3YPoCiLpxRrPaYrBKRSUL5qn2AgFU0koMVlkMOo6G2SIymQCAGE/AGHRsWbCRKc8VmaBN4wBIwkZkFmxkWZDSFCwyommZSABgCmZBSsuiHahA8kA2iZYzSapAsmgHlgfdVyGLTFg3iZqQhAqZB923GGUgQhYRVElmAUXIGGVgedQ9AJJnAkqyClCEkkfdM1Pt13VHdxDpnof0jgxB+mYqO5PaCSDRIAbgDgdpKjtmwm13irsnq4ATdKeYcNvUZAt0dg5NVwEQFKrJlpn45lwh/LpbWdela4K5QsXEN61tytWr81l5YSY/n4wdQH84qjd2J6vEz+W0BOAGgLlE/AMAPQCv6e4gmWYC/QF3d/7zf8P/An4AWL/T1+B2nyIAAAAASUVORK5CYII=) no-repeat scroll 0px 10px;
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
	</style>

	<script src="../resources/jquery-3.5.1.min.js"></script>

	<script>

	(function($){
		$.fn.tablesorter = function() {
			var $table = this;
			this.find('th').click(function() {
				var idx = $(this).index();
				var direction = $(this).hasClass('sort_asc');
				$table.tablesortby(idx,direction);
			});
			return this;
		};

		$.fn.tablesortby = function(idx,direction) {
			var $rows = this.find('tbody tr');
			function elementToVal(a) {
				var $a_elem = $(a).find('td:nth-child('+(idx+1)+')');
				var a_val = $a_elem.attr('data-sort') || $a_elem.text();
				return (a_val == parseInt(a_val) ? parseInt(a_val) : a_val);
			}

			$rows.sort(function(a,b){
				var a_val = elementToVal(a), b_val = elementToVal(b);
				return (a_val > b_val ? 1 : (a_val == b_val ? 0 : -1)) * (direction ? 1 : -1);
			})
			
			this.find('th').removeClass('sort_asc sort_desc');
			$(this).find('thead th:nth-child('+(idx+1)+')').addClass(direction ? 'sort_desc' : 'sort_asc');
			for(var i =0;i<$rows.length;i++)
			this.append($rows[i]);
			this.settablesortmarkers();
			return this;
		}

		$.fn.retablesort = function() {
			var $e = this.find('thead th.sort_asc, thead th.sort_desc');
			if($e.length)
			this.tablesortby($e.index(), $e.hasClass('sort_desc') );

			return this;
		}

		$.fn.settablesortmarkers = function() {
			this.find('thead th span.indicator').remove();
			this.find('thead th.sort_asc').append('<span class="indicator">&darr;<span>');
			this.find('thead th.sort_desc').append('<span class="indicator">&uarr;<span>');
			return this;
		}

	})(jQuery);

	$(function(){
		var XSRF = (document.cookie.match('(^|; )_sfm_xsrf=([^;]*)')||0)[2];
		var MAX_UPLOAD_SIZE = <?php echo $MAX_UPLOAD_SIZE ?>;
		var $tbody = $('#list');
		$(window).on('hashchange',list).trigger('hashchange');
		$('#table').tablesorter();

		$('#table').on('click','.delete',function(data) {
			$.post("",{'do':'delete',file:$(this).attr('data-file'),xsrf:XSRF},function(response){
				list();
			},'json');
			return false;
		});

		$('#mkdir').submit(function(e) {
			var hashval = decodeURIComponent(window.location.hash.substr(1)),
			$dir = $(this).find('[name=name]');
			e.preventDefault();
			$dir.val().length && $.post('?',{'do':'mkdir',name:$dir.val(),xsrf:XSRF,file:hashval},function(data){
				list();
			},'json');
			$dir.val('');
			return false;
		});

		function list() {
			var hashval = window.location.hash.substr(1);
			$.get('?do=list&file='+ hashval,function(data) {
				$tbody.empty();
				$('#breadcrumb').empty().html(renderBreadcrumbs(hashval));
				if(data.success) {
					$.each(data.results,function(k,v){
						$tbody.append(renderFileRow(v));
					});
					!data.results.length && $tbody.append('<tr><td class="empty" colspan=5>This folder is empty</td></tr>')
					data.is_writable ? $('body').removeClass('no_write') : $('body').addClass('no_write');
				} else {
					console.warn(data.error.msg);
				}
				$('#table').retablesort();
			},'json');
		}

		function renderFileRow(data) {
			var $link = $('<a class="name" />')
			.attr('href', data.is_dir ? '#' + encodeURIComponent(data.path) : './' + data.path)
			.text(data.name);
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
			.addClass(data.is_dir ? 'is_dir' : '')
			.append( $('<td class="first" />').append($link) )
			.append( $('<td/>').attr('data-sort',data.is_dir ? -1 : data.size)
			.html($('<span class="size" />').text(formatFileSize(data.size))) )
			.append( $('<td/>').attr('data-sort',data.mtime).text(formatTimestamp(data.mtime)) )
			.append( $('<td/>').text(perms.join('+')) )
			.append( $('<td/>').append($dl_link).append( data.is_deleteable ? $delete_link : '') )
			return $html;
		}

		function renderBreadcrumbs(path) {
			var base = "",
			$html = $('<div/>').append( $('<a href=#>Home</a></div>') );
			$.each(path.split('%2F'),function(k,v){
				if(v) {
					var v_as_text = decodeURIComponent(v);
					$html.append( $('<span/>').text(' ▸ ') )
					.append( $('<a/>').attr('href','#'+base+v).text(v_as_text) );
					base += v + '%2F';
				}
			});
			return $html;
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
	})

	</script>

	<head>

	</head>

	<div>
		<img class="aquila" src="../resources/aquila_large.png">

		<audio id="audio_player" controls> </audio>
	</div>


	<body>
		<div id="top">

		<div id="breadcrumb">&nbsp;</div>
	</div>

	<div id="upload_progress"></div>
	<table id="table"><thead><tr>
		<th>  Name</th>
		<th>Size</th>
		<th>Modified</th>
		<th>Permissions</th>
		<th>Actions</th>
	</tr></thead><tbody id="list">

	</tbody></table>
	<footer></a></footer>
</body></html>
