rule php_webshell {
    meta:
        description = "Detects common PHP webshell patterns"
        author = "MalScan"
        severity = "high"
    strings:
        $eval1 = "eval($_POST[" ascii nocase
        $eval2 = "eval($_GET[" ascii nocase
        $eval3 = "eval($_REQUEST[" ascii nocase
        $eval4 = "eval(base64_decode(" ascii nocase
        $assert1 = "assert($_POST[" ascii nocase
        $assert2 = "assert($_GET[" ascii nocase
        $system1 = "system($_POST[" ascii nocase
        $system2 = "system($_GET[" ascii nocase
        $passthru = "passthru(" ascii nocase
        $shell_exec = "shell_exec(" ascii nocase
        $exec = "exec($_" ascii nocase
        $preg_replace = "preg_replace(\"/.*/e\"" ascii nocase
        $create_function = "create_function(" ascii nocase
    condition:
        any of them
}

rule asp_webshell {
    meta:
        description = "Detects common ASP/ASPX webshell patterns"
        author = "MalScan"
        severity = "high"
    strings:
        $eval1 = "eval(request(" ascii nocase
        $eval2 = "eval request(" ascii nocase
        $execute1 = "execute(request(" ascii nocase
        $execute2 = "execute request(" ascii nocase
        $cmd1 = "cmd.exe /c" ascii nocase
        $cmd2 = "wscript.shell" ascii nocase
        $fso = "scripting.filesystemobject" ascii nocase
        $adodb = "adodb.stream" ascii nocase
    condition:
        any of them
}

rule jsp_webshell {
    meta:
        description = "Detects common JSP webshell patterns"
        author = "MalScan"
        severity = "high"
    strings:
        $runtime1 = "Runtime.getRuntime().exec(" ascii
        $runtime2 = "getRuntime().exec(" ascii
        $processbuilder = "ProcessBuilder(" ascii
        $jscript = "<%@ Page Language=\"Jscript\"" ascii nocase
        $cmd1 = "request.getParameter(\"cmd\")" ascii nocase
        $cmd2 = "request.getParameter(\"command\")" ascii nocase
        $inputstream = "getInputStream()" ascii
    condition:
        any of them
}

rule generic_webshell {
    meta:
        description = "Detects generic webshell indicators"
        author = "MalScan"
        severity = "medium"
    strings:
        $password1 = "password" ascii nocase
        $pass1 = "pass=" ascii nocase
        $b64_eval = "ZXZhbCg" ascii  // base64 of "eval("
        $b64_system = "c3lzdGVtKA" ascii  // base64 of "system("
        $upload = "move_uploaded_file(" ascii nocase
        $chmod = "chmod(" ascii
    condition:
        2 of them
}
