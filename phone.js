var inum=1,vipOption="";
var vipChannl = new Array(
"//z1.m1907.cn/?jx=",
"//api.smq1.com/?url=",
"//jx.hezeshi.net/ce/jlexi.php?url=",
"//api.pangujiexi.com/player.php?url=",
"//aikan-tv.com/?url=",
"//jx.km58.top/jx/?url=",
"//www.3aym.cn/?url=",
"//jiexi.071811.cc/jx.php?url="
);

for (x in vipChannl)
{
  vipOption = vipOption + '<option value="'+vipChannl[x]+'">VIP线路'+inum+++'</option>';
}

function youkuVIP(emID,rID){
	var gemID = document.getElementsByClassName(emID)[0];
	var newNode = document.createElement("select");
	newNode.setAttribute("style","border:2px solid #0088f5;color:#0088f5;outline:0;font-size:14px;margin-left:10px");
	gemID.appendChild(newNode);
	newNode.setAttribute("onchange", "youkuPlayer(this,'"+rID+"')");
	newNode.innerHTML = '<option selected="selected" disabled="disabled">切换VIP线路</option>'+vipOption;
}
function youkuPlayer(e,rID){
    var playerID = document.getElementById(rID);
    var thisURL=window.location.href.match('http[^\?]*')[0];
    playerID.innerHTML = '';
    var newplayerID = document.createElement("iframe");
    playerID.appendChild(newplayerID);
    newplayerID.setAttribute("border","0");
    newplayerID.setAttribute("frameborder","no");
    newplayerID.setAttribute("scrolling","no");
    newplayerID.setAttribute("marginwidth","0");
    newplayerID.setAttribute("width","100%");
    newplayerID.setAttribute("height","190px");
    newplayerID.src = e.value+thisURL;
}
