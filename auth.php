<?php
if(session_status()===PHP_SESSION_NONE){session_start();}
function e($v){return htmlspecialchars((string)$v,ENT_QUOTES,'UTF-8');}
function require_login(){if(empty($_SESSION['user'])){header('Location:index.php');exit;}}
function require_role($roles){require_login(); if(!in_array($_SESSION['user']['role'],$roles,true)){http_response_code(403);exit('Access denied.');}}
function audit($pdo,$action,$details=''){ $s=$pdo->prepare('INSERT INTO audit_log(user_id,action,details) VALUES(?,?,?)');$s->execute([$_SESSION['user']['id']??null,$action,$details]); }
function csrf(){if(empty($_SESSION['csrf']))$_SESSION['csrf']=bin2hex(random_bytes(32));return $_SESSION['csrf'];}
function check_csrf(){if(!hash_equals($_SESSION['csrf']??'',$_POST['csrf']??'')){http_response_code(419);exit('Invalid security token. Refresh and try again.');}}
function can_write(){return in_array($_SESSION['user']['role']??'',['ADMIN','OPERATOR'],true);}
