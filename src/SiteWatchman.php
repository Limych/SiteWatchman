<?php
namespace SiteWatchman;

/********************************************************************************************************
 *
 * @author Limych
 */
class SiteWatchman {

    const VERSION = '0.1.0';

    const ENCRYPTION_METHOD = 'aes128';
    const ENCRYPTION_KEY = '089118b7-000c-4614-b623-5e575128797e';

    const REPORT_DATE_FORMAT = 'Y-m-d H:i';

    protected $filesIterator;

    protected $fileHashes;

    protected $suspicious;

    public static function run($root = __DIR__, $checkPeriod = 5)
    {
        $cfg_dirs = array();
        $dir = $root;
        $cfg_fname = 'sw_'.hash('adler32', self::ENCRYPTION_KEY).'.db';
        while (! file_exists($cfg_fpath = "$dir/$cfg_fname") && ! in_array($dir, $cfg_dirs)) {
            $cfg_dirs[] = $dir;
            $dir = dirname($dir);
        }

        if (file_exists($cfg_fpath) && is_readable($cfg_fpath)) {
            $cfg = @openssl_decrypt(
                file_get_contents($cfg_fpath),
                self::ENCRYPTION_METHOD,
                self::ENCRYPTION_KEY,
                OPENSSL_RAW_DATA
            );
            $sw = unserialize($cfg);
        } else {
            $sw = new self($root);
        }

        $show_report = ! isset($_REQUEST['q']);
        $serialize = ! file_exists($cfg_fpath);
        if (! empty($_GET['file'])) {
            $sw->reportInspectData($_GET['file']);
            $show_report = false;

        } elseif (! empty($_GET['dismiss'])) {
            $serialize |= $sw->dismissWarning($_GET['dismiss']);
            $show_report = false;

        } elseif (! empty($_GET['remove'])) {
            $serialize |= $sw->removeFile($_GET['dismiss']);
            $show_report = false;

        } elseif (! file_exists($cfg_fpath) || (filemtime($cfg_fpath) + $checkPeriod < time())) {
            if (file_exists($cfg_fpath))    @touch($cfg_fpath);
            $serialize |= $sw->runSeek();
        }

        if ($serialize) {
            $cfg = @openssl_encrypt(
                serialize($sw),
                self::ENCRYPTION_METHOD,
                self::ENCRYPTION_KEY,
                OPENSSL_RAW_DATA
            );
            if (file_exists($cfg_fpath)) {
                @file_put_contents($cfg_fpath, $cfg);
            } else {
                do {
                    $cfg_fpath = array_shift($cfg_dirs) . "/$cfg_fname";
                } while ((false === @file_put_contents($cfg_fpath, $cfg)) && ! empty($cfg_dirs));
            }
        }

        if ($show_report) {
            $sw->report();
        }
    }

    public function __construct($root = __DIR__)
    {
        $this->filesIterator = new FilesIterator($root);
        $this->fileHashes = $this->suspicious = array();
    }

    public function runSeek($maxExecutionTime = 1000)
    {
        $serialize = false;
        clearstatcache();
        foreach (array_keys($this->suspicious) as $fpath) {
            if (! file_exists($this->filesIterator->getRoot() . $fpath)) {
                unset($this->suspicious[$fpath]);
                $serialize = true;
            }
        }

        $cnt = 0;
        do {
            $file = $this->filesIterator->getNextRiskyFile();
            $fpath = $this->filesIterator->getRoot() . $file;

            $item = &$this->fileHashes;
            $segments = explode('/', substr($file, 1));
            $isNew = false;
            foreach ($segments as $seg) {
                if (empty($item[$seg])) {
                    $isNew = true;
                    $item[$seg] = array();
                }
                $item = &$item[$seg];
            }

            $hash = $this->hashFile($fpath);
            if (($isNew || $item !== $hash)
            && ! empty($result = FilesInspector::inspect($fpath, $item, $hash))) {
                if (!isset($this->suspicious[$file]))
                    $this->suspicious[$file] = array();
                if (!$isNew)
                    $this->suspicious[$file][] = FilesInspector::msg(FilesInspector::MODIFIED);
                $this->suspicious[$file][] = $result;
                $serialize = true;
            }
            $item = $hash;
        } while (Util::getSpendTime() <= $maxExecutionTime);

        return $serialize;
    }

    public function hashFile($fpath)
    {
        $hash = array(
            filesize($fpath),
            filemtime($fpath),
            hash_file('adler32', $fpath),
        );
        return implode('-', $hash);
    }

    protected function reportHeader()
    {
        ?><!DOCTYPE html>
<html><head>
    <title>SiteWatchman report</title>

    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.css" rel="stylesheet" />
    <link href="https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.css" rel="stylesheet" />

	<script src="https://code.jquery.com/jquery-3.2.1.min.js" integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4=" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/tether/1.4.0/js/tether.min.js" integrity="sha384-DztdAPBWPRXSA/3eYEEUWrWCy7G5KFbe8fFjk5JAIxUYHKkDx6Qin1DkWx51bBrb" crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/js/bootstrap.min.js" integrity="sha384-vBWWzlZJ8ea9aCX4pEW3rVHjgjt7zpkNpZk+02D9phzyeVkE+jo0ieGizqPLForn" crossorigin="anonymous"></script>
    <script type="text/javascript"><!--
    	var _gaq = _gaq || [];
    	_gaq.push([ '_setAccount', 'UA-XXXXXXXX-X' ]);
    	_gaq.push([ '_trackPageview' ]);

    	(function() {
    		var ga = document.createElement('script');
    		ga.type = 'text/javascript';
    		ga.async = true;
    		ga.src = ('https:' == document.location.protocol ? 'https://ssl'
    				: 'http://www')
    				+ '.google-analytics.com/ga.js';
    		var s = document.getElementsByTagName('script')[0];
    		s.parentNode.insertBefore(ga, s);
    	})();
    //--></script>
    <style type="text/css">
    .code {
        -ms-word-break: break-all;
        word-break: break-all;

        /* Non standard for webkit */
        word-break: break-word;

        -webkit-hyphens: auto;
        -moz-hyphens: auto;
        hyphens: auto;
    }
    </style>
</head><body>
<div class="container">
	<h1 class="mt-3 mb-5">SiteWatchman report</h1>
<?php
    }

    public function report()
    {
        $this->reportHeader();

        if (! empty($this->suspicious)):
            foreach ($this->suspicious as $fpath => $statuses):
?>
    <div class="card">
        <div class="card-block">
            <h4 class="card-title"><?=htmlentities($fpath)?></h4>
<?php       foreach ($statuses as $st): ?>
    		<div class="alert <?=(FilesInspector::isHighRisky($st[1]) ? 'alert-danger' : (FilesInspector::isMediumRisky($st[1]) ? 'alert-warning' : 'alert-info'))?>" role="alert">
    			<div><strong><?=date(self::REPORT_DATE_FORMAT, $st[0])?>:</strong> <?=htmlentities(FilesInspector::getStatusMsg($st[1]))?></div>
<?php           if (! empty($st[2])):   ?>
    			<div class="mt-1"><?php $this->reportShowInfo($st[2])?></div>
<?php           endif;  ?>
    		</div>
<?php       endforeach; ?>
    		<div class="text-right">
                <button type="button" class="card-link btn btn-secondary" data-inspect="<?=htmlentities($fpath)?>"><i class="fa fa-search mr-2" aria-hidden="true"></i>Inspect file</button>
            </div>
        </div>
    </div>
<?php
            endforeach;
        else:
?>
	<div class="alert alert-success text-center" role="alert">
		<strong>Well done!</strong> There are no warnings now.
    </div>
<?php
        endif;

        $this->reportFooter();
    }

    protected function reportShowInfo($info)
    {
        if (! empty($info) && empty($res = htmlentities($info))) {
            echo '<pre>' . htmlentities(Util::hexDump($info, false)) . '</pre>';
        } else {
            echo "<code>$res</code>";
        }
    }

    protected function reportFooter()
    {
?>
	<div class="alert alert-info text-right clearfix mt-5" role="alert"><small>Report generated by SiteWatchman v.<?= self::VERSION?>.<br/>© 2017 Andrey Khrolenok</small></div>
</div>

<!-- Modal -->
<script type="text/javascript"><!--
$(function() {
	$('[data-inspect]').click(function() {
		fpath = $(this).attr('data-inspect');
		$("#inspectModalTitle").html("The contents of the file <code>" + fpath + "</code>");
		$("#inspectModal").attr("data-fpath", fpath).modal();
		$("#inspectModalDelete").click(function() {
			fpath = $("#inspectModal").attr("data-fpath");
			if (true == confirm("Are you sure you want to delete file "+fpath+"?\nThis CAN NOT BE UNDONE!")) {
    			$.get("<?=addslashes($_SERVER['PHP_SELF'])?>?remove=" + fpath);
    			$("#inspectModal").modal("hide");
    			$("[data-inspect='"+fpath+"']").parents(".card").remove();
			}
		});
		$("#inspectModalDismiss").click(function() {
			fpath = $("#inspectModal").attr("data-fpath");
			if (true == confirm("Are you sure you want to delete ALL existing warnings about file "+fpath+"?")) {
    			$.get("<?=addslashes($_SERVER['PHP_SELF'])?>?dismiss=" + fpath);
    			$("#inspectModal").modal("hide");
    			$("[data-inspect='"+fpath+"']").parents(".card").remove();
			}
		});
		$("#inspectModal .modal-body")
			.html('<div class="loader text-center my-5"><i class="fa fa-spinner fa-pulse fa-fw mr-1"></i>Loading file content…</div>')
			.load("<?=addslashes($_SERVER['PHP_SELF'])?>?file=" + fpath)
    		;
	});
});

//--></script>
<div class="modal fade" id="inspectModal" tabindex="-1" role="dialog" aria-labelledby="inspectModalTitle" aria-hidden="true">
  <div class="modal-dialog modal-lg" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="inspectModalTitle">Modal title</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body" style="overflow:auto;max-height:calc(95vh - 10rem)"></div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fa fa-times mr-2" aria-hidden="true"></i>Close</button>
        <button id="inspectModalDelete" type="button" class="btn btn-danger"><i class="fa fa-trash mr-2" aria-hidden="true"></i>Delete this file</button>
        <button id="inspectModalDismiss" type="button" class="btn btn-success"><i class="fa fa-check mr-2" aria-hidden="true"></i>Dismiss warning</button>
      </div>
    </div>
  </div>
</div>
</body></html>
<?php
    }

    public function reportInspectData($fpath)
    {
        $fpath = $this->filesIterator->normalizePath($fpath);
        if (! empty($this->suspicious[$fpath]))
            Util::highlightFile($this->filesIterator->getRoot() . $fpath);
        else
            echo '<div class="alert alert-danger" role="alert">The file <code>' . $fpath . '</code> is not in the list of suspicious.</div>';
    }

    public function dismissWarning($fpath)
    {
        $fpath = $this->filesIterator->normalizePath($fpath);
        if (! empty($this->suspicious[$fpath])) {
            unset($this->suspicious[$fpath]);
            return true;
        }
        return false;
    }

    public function removeFile($fpath)
    {
        $fpath = $this->filesIterator->normalizePath($fpath);
        if (! empty($this->suspicious[$fpath])) {
            unset($this->suspicious[$fpath]);
            @unlink($this->filesIterator->getRoot() . $fpath);
            return true;
        }
        return false;
    }

}



/********************************************************************************************************
 *
 * @author Limych
 *
 */
class FilesIterator
{

    protected $root = __DIR__;
    protected $pass = 0;
    protected $dirs = array();
    protected $files = array();

    public function __construct($root = __DIR__)
    {
        $this->root = $root;
    }

    public function getRoot()
    {
        return $this->root;
    }

    public function getPass()
    {
        return $this->pass;
    }

    public function isFirstPass()
    {
        return $this->pass <= 1;
    }

    public function normalizePath($path)
    {
        $segments = explode('/', $path);
        $path = array();
        foreach ($segments as $seg) {
            if ($seg == '..')
                @array_pop($path);
                elseif (! empty($seg) && $seg !== '.')
                $path[] = $seg;
        }
        return '/' . implode('/', $path);
    }

    public function addDir($dir = null)
    {
        if (empty($dir) && !in_array('', $this->dirs)) {
            $this->dirs[] = '';
            return;
        }

        $dir = substr($this->normalizePath($dir), 1);

        if (is_dir($this->root . '/' . $dir) && !in_array($dir, $this->dirs)) {
            if ($this->pass == 0)   $this->pass = 1;
            $this->dirs[] = $dir;
        }
    }

    protected function readNextDir()
    {
        if (empty($this->dirs)) {
            $this->addDir();
            $this->pass++;
        }
        $dir = array_shift($this->dirs);
        if (false !== $handle = @opendir($this->root . '/' . $dir)) {
            while (false !== ($entry = @readdir($handle))) {
                $fpath = $dir . '/' . $entry;
                if ($entry == '.' || $entry == '..') {
                    continue;

                } elseif (is_file($this->root . '/' . $fpath) && is_readable($this->root . '/' . $fpath)) {
                    $this->files[] = $fpath;

                } elseif (is_dir($this->root . '/' . $fpath) && !in_array($fpath, $this->dirs)) {
                    $this->dirs[] = $fpath;
                }
            }
            closedir($handle);
        }
    }

    public function isExecutableFile($fpath)
    {
        static $exts = array(
            // High risk executables
            'ACTION', 'APK', 'APP', 'BAT', 'BIN', 'CMD', 'COM', 'COMMAND', 'CPL', 'CSH',
            'EXE', 'GADGET', 'INF', 'INS', 'INX', 'IPA', 'ISU', 'JOB', 'JSE', 'KSH',
            'LNK', 'MSC', 'MSI', 'MSP', 'MST', 'OSX', 'OUT', 'PAF', 'PIF', 'PRG', 'PS1',
            'REG', 'RGS', 'RUN', 'SCR', 'SCT', 'SHB', 'SHS', 'U3P', 'VB', 'VBE', 'VBS',
            'VBSCRIPT', 'WORKFLOW', 'WS', 'WSF', 'WSH',

            // Web-server executable files
            'PHP', 'PHTML', 'ASP', 'ASPX', 'JSP', 'PHP4', 'PHP3', 'SHTML', 'CGI', 'PL', 'PHAR',
        );

        $ext = strtoupper(pathinfo($fpath, PATHINFO_EXTENSION));
        return is_executable($fpath) || in_array($ext, $exts);
    }

    public function isWebFile($fpath)
    {
        static $exts = array(
            'HTML', 'HTM', 'CSS', 'XHTML', 'JS', 'HTACCESS',
        );

        $ext = strtoupper(pathinfo($fpath, PATHINFO_EXTENSION));
        return in_array($ext, $exts);
    }

    public function isRiskyFile($fpath)
    {
        return $this->isExecutableFile($fpath) || $this->isWebFile($fpath);
    }

    public function getNextFile()
    {
        while (empty($this->files)) {
            $this->readNextDir();
        }
        return array_shift($this->files);
    }

    public function getNextRiskyFile()
    {
        do {
            $fpath = $this->getNextFile();
        } while (! empty($fpath) && ! $this->isRiskyFile($fpath));
        return $fpath;
    }

}



/********************************************************************************************************
 *
 * @author Limych
 *
 */
class FilesInspector
{

    const OK                = false;
    const LOW_RISK          = 0x00000000;
    const MEDIUM_RISK       = 0x00100000;
    const HIGH_RISK         = 0x00200000;
    const STATUS_MASK       = 0x000FFFFF;
    const MODIFIED          = 1;    // File modified
    const STRANGE_MTIME     = 2;    // Strange file modification time behavior
    const LONG_LINE         = 3;    // A very long line of code
    const DANGEROUS_CODE    = 4;    // Dangerous pieces of code are found
    const STRANGE_VARIABLES = 5;    // Strange variable name in code

    const REPORT_DATE_FORMAT = 'Y-m-d H:i:s';

    public static function msg($status, $comment = null)
    {
        return array(
            time(),
            $status,
            $comment
        );
    }

    public static function inspect($fpath, $old_hash, $new_hash)
    {
        static $spc1 = 30;
        static $spc2 = 20;

        if (! ($isNew = empty($old_hash))) {
            $old_hash = explode('-', $old_hash);
        }
        $new_hash = explode('-', $new_hash);
        settype($new_hash[1], 'integer');

        if (! $isNew) {
            settype($old_hash[1], 'integer');

            // Check modification time
            if ($old_hash[1] >= $new_hash[1]) {
                return self::msg(self::STRANGE_MTIME | self::HIGH_RISK,
                    date(self::REPORT_DATE_FORMAT, $old_hash[1]) . ' → ' . date(self::REPORT_DATE_FORMAT, $new_hash[1]));
            }
        }

        $content = @file_get_contents($fpath);

        // Long lines of code
        foreach (preg_split("/[\r\n]+/", $content, null, PREG_SPLIT_NO_EMPTY) as $line) {
            if (strlen($line) > 500)
                return self::msg(self::LONG_LINE | self::HIGH_RISK,
                    substr($line, 0, 100) . '…');
        }

        //         if (self::OK !== $result = self::inspectContent($isNew, $content)) {/*   // For DEBUG only
        if (self::OK === $result = self::inspectContent($isNew, $content)) {/**/
            // Primitive code deobfuscation
            $content = preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/', function($a){ return pack('H*', $a[1]); }, $content);
            $content = preg_replace_callback('/[\'\"]\s*\.\s*\(([0-9\/\*\+\-]+)\)\s*\.\s*[\'\"]/', function($a){
                $calc = create_function('', "return (${a[1]});");
                return 0 + $calc();
            }, $content);
                $content = preg_replace('/[\'\"]\s*\.\s*[\'\"]/', '', $content);

                $result = self::inspectContent($isNew, $content, self::MEDIUM_RISK);
        }

        return $result;
    }

    protected static function inspectContent($isNew, $content, $riskClass = self::LOW_RISK)
    {
        if (! $isNew && ! defined('DEBUG')) {
            // Dangerous code in modified files
            $patterns = implode('|', array(
            '\biframe\b',       '\bunescape\b',     '\bfro'.'mCharCode\b',  '\bmkdir\b',
            '\bchmod\b',        '\bdisplay\b',      '\b(?:https?:)?\/\/',   '\bcreate_function\b',
            '\bgzinflate\b',    '\b(?:href|src)=[\'\"](?:https?:)?\/\/',
            ));
            if (preg_match("/(.{0,$spc1}(?:$patterns).{0,$spc1})/i", $content, $matches)) {
                return self::msg(self::DANGEROUS_CODE | $riskClass, "…$matches[1]…");
            }
        }

        // Common troyan fingerprints
        $patterns = implode('|', array(
        'Fil'.'esMan',      '\btry\s*\{document\.body\b',   '\bString\["fromCh'.'arCode"\]',
        '\bauth_pass\b',    '\bfromCharCode\b',             '\bshell_exec\b',
        '\bpassthru\b',     '\bsystem\s*\(\b',              '\bpasswd\b',
        '\beval\s*\(\s*str_r'.'eplace\b',                   '\beval\s*\(\s*gzinfl'.'ate\b',
        'e2a'.'a4e',        '="";fun'.'ction\b',            '"ev"\+"al",md5=,ss\+st\.fromCh'.'arCode',
        ));
        if (preg_match("/(.{0,$spc1}(?:$patterns).{0,$spc1})/i", $content, $matches)) {
            return self::msg(self::DANGEROUS_CODE | $riskClass | self::HIGH_RISK, "…$matches[1]…");
        }

        // Pack and eval commands in same code
        $patterns = implode('|', array(
        '\bchr\b',          '\bord\b',          '\bbase64_decode\b',        '\bstrtok\b',
        '\bstr_replace\b',  '\bgzinflate\b',
        ));
        $hasPack = preg_match("/(.{0,$spc2}(?:$patterns).{0,$spc2})/i", $content, $packMatches);
        //
        $pattern_var = '\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*';
        $patterns = implode('|', array(
            '\beval\b',         '\bcreate_function\b',      '\bassert\b',       '\bu[ak]?sort\b',
            $pattern_var.'\s*\(',                           '\barray_map\b',    '\$\{.*?\}\s*\(',
            '\bpreg_replace(?:_callback)?\b',                '\binclude(?:_once)?\s*\(?\s*'.$pattern_var,
        ));
        $hasExec = preg_match("/(.{0,$spc2}(?:$patterns).{0,$spc2})/i", $content, $execMatches);
        //
        if ($hasPack && $hasExec) {
            return self::msg(self::DANGEROUS_CODE | $riskClass | self::HIGH_RISK, "…$packMatches[1]… + …$execMatches[1]…");
        }

        // Strange variable names
        $patterns = implode('|', array(
        '\$([a-zA-Z_\x7f-\xff])\\2{2,}',         '\$[_\x7f-\xff]+(?>[^a-zA-Z0-9_\x7f-\xff])',
        ));
        if (preg_match("/(.{0,$spc1}(?:$patterns).{0,$spc1})/i", $content, $matches)) {
            return self::msg(self::STRANGE_VARIABLES | $riskClass, "…$matches[1]…");
        }

        return self::OK;
    }

    public static function isMediumRisky($status)
    {
        if (is_array($status))
            $status = $status[1];
            return 0 !== ($status & self::MEDIUM_RISK);
    }

    public static function isHighRisky($status)
    {
        if (is_array($status))
            $status = $status[1];
            return 0 !== ($status & self::HIGH_RISK);
    }

    public static function getStatusMsg($status)
    {
        switch ($status & self::STATUS_MASK) {
            default:                        return '';
            case self::MODIFIED:            return 'File modified';
            case self::STRANGE_MTIME:       return 'Strange file modification time behavior';
            case self::LONG_LINE:           return 'A very long line of code';
            case self::DANGEROUS_CODE:      return 'Dangerous pieces of code are found';
            case self::STRANGE_VARIABLES:   return 'Strange variable name in code';
        }
    }

}



/********************************************************************************************************
 * Assorted static functions.
 *
 * @author Limych
 */
class Util
{

    /**
     * Get script spend time.
     *
     * @return number Spend time in milliseconds
     *
     * @copyright https://stackoverflow.com/users/5747291/martin
     */
    public static function getSpendTime()
    {
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            // On Windows: The real time is measured.
            $spendMiliseconds = (microtime(true) - $_SERVER['REQUEST_TIME_FLOAT']) * 1000;
        } else {
            // On Linux: Any time spent on activity that happens outside the execution
            //           of the script such as system calls using system(), stream operations
            //           database queries, etc. is not included.
            //           @see http://php.net/manual/en/function.set-time-limit.php
            $resourceUsages = getrusage();
            $spendMiliseconds = $resourceUsages['ru_utime.tv_sec'] * 1000 + $resourceUsages['ru_utime.tv_usec'] / 1000;
        }
        return $spendMiliseconds;
    }

    /**
     * Check if more that `$miliseconds` ms remains
     * to error `PHP Fatal error: Maximum execution time exceeded`
     *
     * @param  number $miliseconds
     * @return bool
     *
     * @copyright https://stackoverflow.com/users/5747291/martin
     */
    public static function isRemainingExecutionTimeBiggerThan($miliseconds = 5000)
    {
        $max_execution_time = ini_get('max_execution_time');
        if ($max_execution_time === 0) {
            // No script time limitation
            return true;
        }
        $remainingMiliseconds = $max_execution_time * 1000 - self::getSpendTime();
        return ($remainingMiliseconds >= $miliseconds);
    }

    /**
     * Return or print traditional hex dump of $data.
     *
     * @param string $data Data to be dumped
     * @param boolean $print If true dump will be printed, instead of returned
     * @param string $newline Character will be used to make new line
     * @return string|null Dump or null if it was printed
     *
     * @link https://stackoverflow.com/a/4225813
     * @copyright https://stackoverflow.com/users/283851/mindplay-dk
     */
    public static function hexDump($data, $print = true, $newline = "\n")
    {
        static $from = '';
        static $to = '';

        static $width = 16; // number of bytes per line

        static $pad = '.'; // padding for non-visible characters

        if ($from === '') {
            for ($i = 0; $i <= 0xFF; $i++) {
                $from .= chr($i);
                $to .= ($i >= 0x20 && $i <= 0x7E) ? chr($i) : $pad;
            }
        }

        $hex = str_split(bin2hex($data), $width*2);
        $chars = str_split(strtr($data, $from, $to), $width);

        $offset = 0;
        $result = '';
        foreach ($hex as $i => $line) {
            list($left, $right) = str_split($line, $width);
            $left = implode(' ', str_split($left, 2));
            $right = implode(' ', str_split($right, 2));
            $line = "$left  $right";

            $result .= sprintf('%6X : %-'.($width*3).'s [%-'.$width.'s]', $offset, $line, $chars[$i]) . $newline;
            $offset += $width;
        }

        if ($print) echo $result;
        else        return $result;
    }

    public static function highlightFile($file) {
        // Strip code and first span
        $code = substr(highlight_file($file, true), 36, -15);
        // Split lines
        $code = explode('<br />', $code);
        // Re-Print the code and span again
        echo '<div class="code"><span class="num"></span>' . implode('<br /><span class="num"></span>', $code) . '</div>';
    }

}



/********************************************************************************************************/

setlocale(LC_ALL,'en_US.UTF-8');

SiteWatchman::run('d:\OpenServer\domains');
