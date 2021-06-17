<?php
require('sdk.php');
require('AlbisConfig.php');
$ENDPOINT = "";
$API_STAGE = "staging";
$config = new AlbisConfig($ENDPOINT,$API_STAGE);
if(isset($_GET['call'])){
    $albis = new Albis\Sdk\Albis($config);
    if($_GET['call'] == 'token'){
        echo $albis->getAlbisToken();
    }else if($_GET['call'] == 'tokenforce'){
        echo $albis->getAlbisToken(false,true);
    }else if($_GET['call'] == 'ping'){
        echo $albis->doPing();
    }else if($_GET['call'] == 'echo'){
        echo $albis->doEcho($_GET['echo']);
    }else if($_GET['call'] == 'salutations'){
        echo $albis->getSalutations();
    }else if($_GET['call'] == 'legalforms'){
        echo $albis->getLegalForms();
    }else if($_GET['call'] == 'productgroups'){
        echo $albis->getProductGroups();
    }else if($_GET['call'] == 'getApp'){
        $obj = $albis->findApplication($_GET['id'],$config->GET_RETURN_TYPE_OBJECT());
        echo json_encode($obj);
    }else if($_GET['call'] == 'saveApp'){
        $obj = Albis::getRequestBodyJSONArray();
        echo $albis->saveApplication($obj); 
    }             
            
    exit();
}
if(isset($_GET['doc_get'])){
    $albis = new Albis\Sdk\Albis($config);
    $bas64 = $albis->getDocuments($_GET['applicationId'],$_GET['purchasePrice'],$_GET['iban'],$_GET['rate']);
    header('Content-Description: File Transfer');
    header("Content-type: application/octet-stream");
    header("Content-disposition: attachment; filename=document.pdf");
    echo base64_decode($bas64);
    exit();
}

?>
<div id="wrapper">    
    <div id="tokenFormWrapper">
        <h2>Credentials</h2>
        <form id="tokenForm">
               Username:<input type="text" name="username" value="" /><br />
               Password:<input type="text" name="password" value="" /><br />
               auth0Username:<input type="text" name="auth0Username" value="" /> <br />
               auth0Password:<input type="text" name="auth0Password" value="" /><br />
               realm:<input type="text" name="realm" value="testUsers" />        
        </form>    
        Token:<br />
        <textarea id="tokenText"></textarea><br />
        <button onclick="testToken(false);">get Token</button>
        <button onclick="testToken(true);">get Token (force renew)</button>
    </div>  
    <div id="basicFunctionsWrapper">
        <h2>basic functions</h2>
        <button onclick="testPing()">ping</button><br />
        <button onclick="testEcho()">Echo</button><input type="text" id="echoText" /><br />
        Response:<br />
        <textarea id="basicResponse"></textarea>
    </div>
    <div id="basicFunctionsWrapper">
        <h2>base data</h2>
        <button onclick="testSalutations()">get salutations</button><br />
        <button onclick="testLegalForms()">get legal forms</button><br />
        <button onclick="testProductGroups()">get product groups</button><br />
        Response:<br />
        <textarea id="baseDataResponse"></textarea>
    </div>
    <div id="applicationsWrapper">
        <h2>Application</h2>
        <button onclick="loadApp()">load Application</button>
        <button onclick="saveApp()" id="updateAppButton" disabled="disabled">update Application</button>
        <form id="applicationForm">
            applicationId:<input value="271840" name="applicationId" id="applicationId" type="text" />        
            <br /><span id="applicationFormAutoFill"></span>
        </form>
    </div>
    <div id="documentsWrapper">
        <h2>Documents</h2>    
        <form action="" method="GET" target="_blank">
            applicationId:<input type="text" value="271840" name="applicationId" class="documentInput" /><br />
            purchasePrice:<input type="text" value="5000" name="purchasePrice" class="documentInput" /><br />
            iban:<input type="text" value="DE88100900001234567892" name="iban" class="documentInput" /><br />
            rate:<input type="text" value="300" name="rate" class="documentInput" /><br />          
           <input type="hidden" name="doc_get" value="1" />
            <input type="submit" name="getDoc" value="get documents" />
        </form>
    </div>
</div>
<script language="javascript" type="text/javascript">

function saveApp(){
    var id = document.getElementById("applicationId").value;
    if(id == null || id == ""){
        alert("please enter application id");
        return;
    }
    callSdk("saveApp",function(rsp){
        alert(rsp);
    },"&id=" + encodeURIComponent(id),"applicationForm");
}

function loadApp(){
    var id = document.getElementById("applicationId").value;
    if(id == null || id == ""){
        alert("please enter application id");
        return;
    }
    callSdk("getApp",function(rsp){
        var obj = JSON.parse(rsp);
        var htm = objToForm(obj);                     
        document.getElementById("applicationFormAutoFill").innerHTML = htm;
        document.getElementById("updateAppButton").disabled = false;
    },"&id=" + encodeURIComponent(id));
}

function objToForm(obj){
    var htm = "";
    if(obj == null)return "null"; 
    Object.keys(obj).forEach(function(k){
        var type = typeof obj[k];
        if("object" == type){
            htm += "<h3>"+k+"</h3>" + objToForm(obj[k]) + "<h3>end "+k+"</h3>";
        }else{
            htm += k + ": <input type='"+(type == "number" ? "number" : "text")+"' value='"+obj[k]+"' name='"+k+"' + id='"+k+"' /><br />"    
        }          
    });
    return htm;
}

function testProductGroups(){
     callSdk("productgroups",function(rsp){
        document.getElementById("baseDataResponse").innerHTML = rsp;
    });
}

function testLegalForms(){
    callSdk("legalforms",function(rsp){
        document.getElementById("baseDataResponse").innerHTML = rsp;
    });
}

function testSalutations(){
    callSdk("salutations",function(rsp){
        document.getElementById("baseDataResponse").innerHTML = rsp;
    }); 
}

function testEcho(){
    callSdk("echo",function(rsp){
        document.getElementById("basicResponse").innerHTML = rsp;
    },"&echo=" + encodeURIComponent(document.getElementById("echoText").value));    
}

function testPing(){
    callSdk("ping",function(rsp){
        document.getElementById("basicResponse").innerHTML = rsp;
    });
}

function testToken(forceRenew = false){
    callSdk("token" + (forceRenew ? 'force' : ''),function(rsp){
        document.getElementById("tokenText").innerHTML = rsp;
        document.getElementById("tokenText").value = rsp;
    });       
}

function callSdk(call,func = -1,extraGet = "",bodyJsonForm = "tokenForm"){
    var tokenJson = formToJson(bodyJsonForm);
    var xmlhttp = new XMLHttpRequest();   // new HttpRequest instance 
    xmlhttp.open("POST", "/testsuite.php?call="+call + extraGet);
    xmlhttp.setRequestHeader("Content-Type", "application/json");
    xmlhttp.onreadystatechange = function () {
        if (this.readyState == 4) {
           if(func !== -1)func(xmlhttp.responseText); 
        }
    };
    xmlhttp.send(tokenJson);
    
}

function formToJson(formId){
    var inputs = document.getElementById(formId).getElementsByTagName("input");
    var ret = {};
    for(var i = 0; i < inputs.length; ++i){
        ret[inputs[i].name] = inputs[i].value;
    }
    return JSON.stringify(ret);   
}


</script>