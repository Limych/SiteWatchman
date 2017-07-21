@ECHO OFF
call devtools\encode.bat src\SiteWatchman.php dist\
copy src\swcon.php dist\ >nul
copy .\LICENSE dist\ >nul
