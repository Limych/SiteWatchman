<?php
/*******************************************************************************
 *
 * SiteWatchman — is utility to continuously check your site content for malware.
 *
 * Copyright (C) 2017 Andrey Khrolenok
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @package SiteWatchman
 * @author Limych
 * @link https://github.com/Limych/SiteWatchman
 *
 *******************************************************************************/



// Workaround for magic constant; for now because of php 5.2 issue
if (! defined('__DIR__')) define('__DIR__', dirname(__FILE__));



/**
 *
 * @author Limych
 */
class SiteWatchman {

    const VERSION = '0.2.0';

    const ENCRYPTION_METHOD = 'aes128';
    const ENCRYPTION_KEY = '089118b7-000c-4614-b623-5e575128797e';

    const REPORT_DATE_FORMAT = 'Y-m-d H:i';

    protected $filesIterator;

    protected $fileHashes;

    protected $suspicious;

    public static function run($root = null, $checkPeriod = 5)
    {
        if (empty($root)) {
            if (defined('SW_ROOT'))     $root = SW_ROOT;
            if (empty($root))           $root = __DIR__;
        }

        $cfg_fname = hash('adler32', self::ENCRYPTION_KEY).'.db';
        $dir = $root;
        $cfg_dirs = array();
        while (! @file_exists($cfg_fpath = "$dir/$cfg_fname") && ! in_array($dir, $cfg_dirs)) {
            $cfg_dirs[] = $dir;
            $dir = dirname($dir);
        }
        if (! @file_exists($cfg_fpath)) {
            $dir = __DIR__;
            while (! @file_exists($cfg_fpath = "$dir/$cfg_fname") && ! in_array($dir, $cfg_dirs)) {
                $cfg_dirs[] = $dir;
                $dir = dirname($dir);
            }
        }

        if (@file_exists($cfg_fpath) && is_readable($cfg_fpath) && (false !== $cfg = file_get_contents($cfg_fpath))) {
            $cfg = gzinflate($cfg);
            $sw = unserialize($cfg);
        } else {
            $sw = new self($root);
        }

        $stelth_mode = (count(get_included_files()) == 1) || ! (defined('SW') && SW == 'SiteWatchman');
        $show_report = ! $stelth_mode;
        $serialize = ! @file_exists($cfg_fpath);
        if (! $stelth_mode && ! empty($_GET['file'])) {
            $sw->reportInspectData($_GET['file']);
            $show_report = false;

        } elseif (! $stelth_mode && ! empty($_GET['dismiss'])) {
            $serialize |= $sw->dismissWarning($_GET['dismiss']);
            $show_report = false;

        } elseif (! $stelth_mode && ! empty($_GET['remove'])) {
            $serialize |= $sw->removeFile($_GET['dismiss']);
            $show_report = false;

        } elseif (! @file_exists($cfg_fpath) || (filemtime($cfg_fpath) + $checkPeriod < time())) {
            if (@file_exists($cfg_fpath))    @touch($cfg_fpath);
            $serialize |= $sw->runSeek();
        }

        if ($serialize) {
            $cfg = gzdeflate(serialize($sw), 9);
            if (@file_exists($cfg_fpath)) {
                @file_put_contents($cfg_fpath, $cfg);
            } else {
                do {
                    $cfg_fpath = array_shift($cfg_dirs) . "/$cfg_fname";
                } while ((false === @file_put_contents($cfg_fpath, $cfg)) && ! empty($cfg_dirs));
            }
        }

        if (! $stelth_mode && $show_report) {
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
            if (($isNew || $item !== $hash) && ($result = FilesInspector::inspect($fpath, $item, $hash))) {
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

	<meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="robots" content="none" />

    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.css" rel="stylesheet" />
    <link href="https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.css" rel="stylesheet" />

	<script src="https://code.jquery.com/jquery-3.2.1.min.js" integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4=" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/tether/1.4.0/js/tether.min.js" integrity="sha384-DztdAPBWPRXSA/3eYEEUWrWCy7G5KFbe8fFjk5JAIxUYHKkDx6Qin1DkWx51bBrb" crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/js/bootstrap.min.js" integrity="sha384-vBWWzlZJ8ea9aCX4pEW3rVHjgjt7zpkNpZk+02D9phzyeVkE+jo0ieGizqPLForn" crossorigin="anonymous"></script>
    <script type="text/javascript"><!--
      (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
      (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
      m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
      })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');

      ga('create', 'UA-289367-16', 'auto');
      ga('send', 'pageview');
    //--></script>
    <style type="text/css">
    code, .code {
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

    public static function report_helper($a, $b)
    {
        $ai = 0;
        foreach ($a as $st) {
            $ai += (FilesInspector::isHighRisky($st[2]) ? 4
                : (FilesInspector::isMediumRisky($st[2]) ? 2 : 1));
        }

        $bi = 0;
        foreach ($b as $st) {
            $bi += (FilesInspector::isHighRisky($st[2]) ? 4
                : (FilesInspector::isMediumRisky($st[2]) ? 2 : 1));
        }

        return ($ai == $bi ? 0 : ($ai > $bi ? -1 : 1));
    }

    public function report()
    {
        $this->reportHeader();

        if (! empty($this->suspicious)):
            $suspicious = uasort($this->suspicious, __CLASS__ . '::report_helper');
            foreach ($this->suspicious as $fpath => $statuses):
?>
    <div class="card">
        <div class="card-block">
            <h4 class="card-title"><?=htmlentities($fpath)?></h4>
<?php
            foreach ($statuses as $st):
                $date = array_shift($st);
                $risk = array_shift($st);
?>
    		<div class="alert <?=(FilesInspector::isHighRisky($risk) ? 'alert-danger' : (FilesInspector::isMediumRisky($risk) ? 'alert-warning' : 'alert-info'))?>" role="alert">
    			<div><strong><?=date(self::REPORT_DATE_FORMAT, $date)?>:</strong> <?=htmlentities(FilesInspector::getStatusMsg($risk))?></div>
<?php           if (! empty($st)):   ?>
    			<div class="mt-1"><?php self::reportShowInfo($st)?></div>
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

    protected static function reportShowInfo_helper($info)
    {
        return htmlspecialchars(preg_replace('/[\x00-\x1F\x7F-\xA0\xAD]/', '.', $info));
    }

    protected static function reportShowInfo($info)
    {
        // TODO Remove or fix it?..
//         if (! empty($info) && ('' === $res = htmlentities($info))) {
//             echo '<pre>' . htmlentities(Util::hexDump($info, false)) . '</pre>';
//         } else {
            $info = array_map(__CLASS__ . '::reportShowInfo_helper', $info);
            $info = '<code>' . implode('</code> + <code>', $info) . '</code>';
            $info = strtr($info, array(
                '<code>&amp;hellip;'    => '&hellip;<code>',
                '&amp;hellip;</code>'   => '</code>&hellip;',
            ));
            echo $info;
//         }
    }

    protected function reportFooter()
    {
?>
	<div class="alert alert-info text-right clearfix mt-5 small" role="alert">
		Report generated by <a href="https://github.com/Limych/SiteWatchman" target="_blank">SiteWatchman</a> v.<?= self::VERSION?>.<br/>
		Copyright © 2017 Andrey Khrolenok
	</div>
</div>

<!-- Modal -->
<script type="text/javascript"><!--
$(function() {
	$('[data-inspect]').click(function() {
		fpath = $(this).attr('data-inspect');
		$("#inspectModalTitle").html("The contents of the file <code>" + fpath + "</code>");
		$("#inspectModal").attr("data-fpath", fpath).modal();
		$("#inspectModal .modal-body")
			.html('<div class="loader text-center my-5"><i class="fa fa-spinner fa-pulse fa-fw mr-1"></i>Loading file content…</div>')
			.load("<?=addslashes($_SERVER['PHP_SELF'])?>?file=" + fpath)
    		;
	});
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
        <button id="inspectModalDelete" type="button" class="btn btn-danger"><i class="fa fa-trash mr-2" aria-hidden="true"></i>Delete<span class="hidden-xs-down"> this file</span></button>
        <button id="inspectModalDismiss" type="button" class="btn btn-success"><i class="fa fa-check mr-2" aria-hidden="true"></i>Dismiss<span class="hidden-xs-down"> warning</span></button>
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



/**
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

    public static function isExecutableFile($fpath)
    {
        static $exts = array(
            // High risk executables
            'ACTION', 'APK', 'APP', 'BAT', 'BIN', 'CMD', 'COM', 'COMMAND', 'CPL', 'CSH',
            'EXE', 'GADGET', 'INF', 'INS', 'INX', 'IPA', 'ISU', 'JOB', 'JSE', 'KSH',
            'LNK', 'MSC', 'MSI', 'MSP', 'MST', 'OSX', 'OUT', 'PAF', 'PIF', 'PRG', 'PS1',
            'REG', 'RGS', 'RUN', 'SCR', 'SCT', 'SHB', 'SHS', 'U3P', 'VB', 'VBE', 'VBS',
            'VBSCRIPT', 'WORKFLOW', 'WS', 'WSF', 'WSH',

            // Web-server executable files
            'PHP', 'PHTML', 'ASP', 'ASPX', 'JSP', 'PHP4', 'PHP3', 'SHTML', 'CGI', 'PL',
        );

        $ext = strtoupper(pathinfo($fpath, PATHINFO_EXTENSION));
        return @is_executable($fpath) || in_array($ext, $exts);
    }

    public static function isWebFile($fpath)
    {
        static $exts = array(
            'HTML', 'HTM', 'CSS', 'XHTML', 'JS', 'HTACCESS',
        );

        $ext = strtoupper(pathinfo($fpath, PATHINFO_EXTENSION));
        return in_array($ext, $exts);
    }

    public static function isRiskyFile($fpath)
    {
        return self::isExecutableFile($fpath) || self::isWebFile($fpath);
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
        } while (! empty($fpath) && ! self::isRiskyFile($fpath));
        return $fpath;
    }

}



/**
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
        $args = func_get_args();
        $status = array_shift($args);
        if ((1 == count($args)) && is_array($args[0])) {
            $args = $args[0];
        }
        array_unshift($args, $status);
        array_unshift($args, time());
        return $args;
    }

    public static function inspect($fpath, $old_hash, $new_hash)
    {
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
        // TODO Ignore html-s only trougth first pass
        foreach (preg_split("/[\r\n]+/", $content, null, PREG_SPLIT_NO_EMPTY) as $line) {
            if (strlen($line) > 500)
                return self::msg(self::LONG_LINE | self::HIGH_RISK,
                    substr($line, 0, 100) . '&hellip;');
        }

        if (self::OK === $result = self::inspectContent($isNew, $content)) {
            // No warnings? Ok, let's try inspect de-obfuscated code

            // Primitive code deobfuscation
            $fn = create_function('$a', 'return pack("H*", $a[1]);');
            $content = preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/', $fn, $content);
            $fn = create_function('$a', '$calc = create_function("", "return (${a[1]});"); return 0 + $calc();');
            $content = preg_replace_callback('/[\'\"]\s*\.\s*\(([0-9\/\*\+\-]+)\)\s*\.\s*[\'\"]/', $fn, $content);
            $content = preg_replace('/[\'\"]\s*\.\s*[\'\"]/', '', $content);

            $result = self::inspectContent($isNew, $content, self::MEDIUM_RISK);
        }

        return $result;
    }

    protected static function inspectContent($isNew, $content, $riskClass = self::LOW_RISK)
    {
        static $spc1 = 30;
        static $spc2 = 20;

        if (! $isNew) {
            // Dangerous code in modified files
            $patterns = implode('|', array(
                '\biframe\b',       '\bunescape\b',     '\bfro'.'mCharCode\b',  '\bmkdir\b',
                '\bchmod\b',        '\bdisplay\b',      '\b(?:https?:)?\/\/',   '\bcreate_function\b',
                '\bgzinflate\b',    '\b(?:href|src)=[\'\"](?:https?:)?\/\/',
            ));
            if (preg_match("/(.{0,$spc1}(?:$patterns).{0,$spc1})/i", $content, $matches)) {
                return self::msg(self::DANGEROUS_CODE | $riskClass, "&hellip;$matches[1]&hellip;");
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
            return self::msg(self::DANGEROUS_CODE | $riskClass | self::HIGH_RISK,
                "&hellip;$matches[1]&hellip;");
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
            return self::msg(self::DANGEROUS_CODE | $riskClass | self::HIGH_RISK,
                "&hellip;$packMatches[1]&hellip;", "&hellip;$execMatches[1]&hellip;");
        }

        // Strange variable names
        $patterns = implode('|', array(
            '\$([a-zA-Z_\x7f-\xff])\\2{2,}',         '\$[_\x7f-\xff]+(?>[^a-zA-Z0-9_\x7f-\xff])',
        ));
        if (preg_match("/(.{0,$spc1}(?:$patterns).{0,$spc1})/i", $content, $matches)) {
            return self::msg(self::STRANGE_VARIABLES | $riskClass, "&hellip;$matches[1]&hellip;");
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
            case self::DANGEROUS_CODE:      return 'Potentially dangerous pieces of code are found';
            case self::STRANGE_VARIABLES:   return 'Strange variable name in code';
        }
    }

}



/**
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
            $spendMiliseconds = (microtime(true) - $_SERVER['REQUEST_TIME']) * 1000;
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
            @list($left, $right) = str_split($line, $width);
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



/*******************************************************************************/

setlocale(LC_ALL,'en_US.UTF-8');

SiteWatchman::run();
