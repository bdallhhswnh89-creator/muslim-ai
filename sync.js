/* ════════════════════════════════════════════════════════════════════
   مسلم AI — طبقة مزامنة السيرفر (شاملة)
   • كل مفاتيح mai_* تتزامن تلقائياً لكل مستخدم (محادثات، إعدادات،
     شخصية النموذج، الصوت، القارئ، إعدادات المصحف والتسميع، كل حاجة)
   • مفاتيح الأدمن عالمية: كل المستخدمين بيستلموها من السيرفر،
     والأدمن هو اللي يكتبها من لوحة التحكم
   • localStorage يظل كـ cache أوفلاين — لو السيرفر وقع التطبيق يشتغل
   ════════════════════════════════════════════════════════════════════ */
(function(){
'use strict';
var TOKEN_KEY='mai_token';
var ADMIN_TOKEN_KEY='mai_admin_token';
var SKIP=['mai_token','mai_pub_draft','mai_quran_ask'];
var GLOBAL=['mai_admin_sources_v4','mai_admin_instructions','mai_feature_toggles',
 'mai_suggs','mai_maintenance','mai_maintenance_msg','mai_muftis_custom','mai_muftis_hidden'];
function tok(){try{return localStorage.getItem(TOKEN_KEY)||''}catch(e){return ''}}
function atok(){try{return localStorage.getItem(ADMIN_TOKEN_KEY)||''}catch(e){return ''}}
function isGlobal(k){return GLOBAL.indexOf(k)>-1}
function snapshot(){
 var o={};
 try{
  for(var i=0;i<localStorage.length;i++){
   var k=localStorage.key(i);
   if(!k||k.indexOf('mai_')!==0||SKIP.indexOf(k)>-1||isGlobal(k))continue;
   var v=localStorage.getItem(k);
   if(v==null)continue;
   try{o[k]=JSON.parse(v)}catch(e2){o[k]=v}
  }
 }catch(e){}
 return o;
}
var pushT=null,pushing=false,pulling=false;
function schedulePush(){if(!tok())return;clearTimeout(pushT);pushT=setTimeout(pushNow,1200);}
async function pushNow(){
 if(!tok()||pushing||pulling)return;pushing=true;
 try{
  await fetch('/api/data',{method:'PUT',
   headers:{'Content-Type':'application/json','Authorization':'Bearer '+tok()},
   body:JSON.stringify(snapshot())});
  /* الأدمن يدفع الإعدادات العالمية */
  if(atok()){
   var g={};
   GLOBAL.forEach(function(k){var v=null;try{v=localStorage.getItem(k)}catch(e){}
    if(v!=null){try{g[k]=JSON.parse(v)}catch(e2){g[k]=v}}});
   try{await fetch('/api/global',{method:'PUT',
    headers:{'Content-Type':'application/json','X-Admin-Token':atok()},
    body:JSON.stringify(g)});}catch(e){}
  }
 }catch(e){}
 pushing=false;
}
async function pull(){
 if(!tok()||pulling)return false;pulling=true;
 try{
  var r=await fetch('/api/data',{headers:{'Authorization':'Bearer '+tok()}});
  if(r.ok){
   var d=await r.json();
   Object.keys(d.data||{}).forEach(function(k){
    try{localStorage.setItem(k,typeof d.data[k]==='string'?d.data[k]:JSON.stringify(d.data[k]))}catch(e){}
   });
  }
  /* الإعدادات العالمية من الأدمن — تتطبق على كل المستخدمين */
  try{
   var rg=await fetch('/api/global');
   if(rg.ok){
    var dg=await rg.json();
    Object.keys(dg||{}).forEach(function(k){
     try{localStorage.setItem(k,typeof dg[k]==='string'?dg[k]:JSON.stringify(dg[k]))}catch(e){}
    });
   }
  }catch(e){}
  /* المجتمع العالمي */
  try{
   var rc=await fetch('/api/community');
   if(rc.ok){var dc=await rc.json();if(Array.isArray(dc.posts))localStorage.setItem('mai_community_posts',JSON.stringify(dc.posts));}
  }catch(e){}
  return true;
 }catch(e){return false}
 finally{pulling=false;}
}
/* اعتراض أي كتابة mai_* — أي تغيير في أي صفحة من الست يتزامن تلقائياً */
try{
 var orig=localStorage.setItem.bind(localStorage);
 localStorage.setItem=function(k,v){
  orig(k,v);
  if(k===TOKEN_KEY||k===ADMIN_TOKEN_KEY)return;
  if(typeof k==='string'&&k.indexOf('mai_')===0)schedulePush();
 };
}catch(e){}
window.MaiSync={push:schedulePush,pull:pull,logged:function(){return !!tok()}};
window.addEventListener('focus',function(){pull()});
document.addEventListener('visibilitychange',function(){if(!document.hidden)pull()});
})();
