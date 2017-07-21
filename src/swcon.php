<?php

/**
 * Place here absolute or relative path to SiteWatchman script.
 */
define('SW_PATH', './SiteWatchman.php');

/**
 * You can place here path to root of directories to process by script.
 * If you skip definition of SW_ROOT, SiteWatchman script current directory will be used.
 * To skip definition just comment or delete line below.
 */
define('SW_ROOT', '..');



/***   !!! DON'T EDIT anything below this line !!!   ***************************************/

define('SW', 'SiteWatchman');   // Special constant to switch off stelth mode of script
include SW_PATH;
