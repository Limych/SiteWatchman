#!/usr/bin/env php
<?php

define('ROOT', dirname(dirname(__FILE__)));
define('SRC', ROOT . '/src');
define('DIST', ROOT . '/dist');

define('OBFUSCATOR', dirname(__FILE__) . '/obfuscate.php');


// Clear DIST
foreach (scandir(DIST) as $fpath) {
    if (is_file(DIST . DIRECTORY_SEPARATOR . $fpath))
        unlink(DIST . DIRECTORY_SEPARATOR . $fpath);
}

$sw_dist_fname = hash('adler32', time()).'.php';

$data = file_get_contents(SRC . '/swcon.php');
$data = preg_replace("|'\./SiteWatchman.php'|", "'./$sw_dist_fname'", $data);
file_put_contents(DIST . '/swcon.php', $data);

if (file_exists(OBFUSCATOR)) {
    $argv = array(OBFUSCATOR, SRC . '/SiteWatchman.php', DIST . DIRECTORY_SEPARATOR . $sw_dist_fname);
    include OBFUSCATOR;

} else {
    copy(SRC . '/SiteWatchman.php', DIST . DIRECTORY_SEPARATOR . $sw_dist_fname);
}
