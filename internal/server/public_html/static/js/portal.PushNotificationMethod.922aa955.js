import{i as N,G as B,bm as A,bn as M,bo as G,r as s,j as n,h as v,m as E,T as R,l as U,au as k,R as O}from"./index.2cf54ca8.js";import{F as H}from"./components.FailureIcon.9f6e5683.js";import{P as j}from"./portal.SecondFactorForm.b9c4511d.js";import{S as W}from"./portal.Authenticated.aec66e93.js";import{u as Q}from"./hooks.Mounted.ac24f621.js";import{u as Y}from"./hooks.Workflow.6e7bd503.js";import{C as $}from"./layouts.Login.3ab4a287.js";import{B as w,b as y}from"./mui.Toolbar.c29f3336.js";import{S as x,D as q}from"./portal.MethodContainer.1b18e563.js";import"./components.TimerIcon.f2cea1d7.js";import"./index.8057fcfb.js";function z(e,d,o){return N(M,{targetURL:e,workflow:d,workflowID:o})}async function J(){return B(G)}async function K(e){return N(A,{device:e.device,method:e.method})}const V=function(e){const[d,o]=s.useState(1),[t,u]=s.useState([]),b=c=>{c.methods.length===1?f(c.methods[0],c.id):(u(c),o(2))},f=(c,a)=>{a?e.onSelect({id:a,method:c}):e.onSelect({id:t.id,method:c})};let r;switch(d){case 1:r=n.jsx(v,{container:!0,justifyContent:"center",spacing:1,id:"device-selection",children:e.devices.map((c,a)=>n.jsx(X,{id:a,device:c,onSelect:()=>b(c)},a))});break;case 2:r=n.jsx(v,{container:!0,justifyContent:"center",spacing:1,id:"method-selection",children:t.methods.map((c,a)=>n.jsx(Z,{id:a,method:c,onSelect:()=>f(c)},a))});break}return n.jsxs($,{children:[r,n.jsx(w,{color:"primary",onClick:e.onBack,id:"device-selection-back",children:"back"})]})},X=function(e){const d="device-option-"+e.id,o="device-"+e.device.id,t=E(u=>({item:{paddingTop:u.spacing(4),paddingBottom:u.spacing(4),width:"100%"},icon:{display:"inline-block",fill:"white"},buttonRoot:{display:"block"}}))();return n.jsx(v,{item:!0,xs:12,className:d,id:o,children:n.jsxs(w,{className:t.item,color:"primary",classes:{root:t.buttonRoot},variant:"contained",onClick:e.onSelect,children:[n.jsx(y,{className:t.icon,children:n.jsx(j,{width:32,height:32})}),n.jsx(y,{children:n.jsx(R,{children:e.device.name})})]})})},Z=function(e){const d="method-option-"+e.id,o="method-"+e.method,t=E(u=>({item:{paddingTop:u.spacing(4),paddingBottom:u.spacing(4),width:"100%"},icon:{display:"inline-block",fill:"white"},buttonRoot:{display:"block"}}))();return n.jsx(v,{item:!0,xs:12,className:d,id:o,children:n.jsxs(w,{className:t.item,color:"primary",classes:{root:t.buttonRoot},variant:"contained",onClick:e.onSelect,children:[n.jsx(y,{className:t.icon,children:n.jsx(j,{width:32,height:32})}),n.jsx(y,{children:n.jsx(R,{children:e.method})})]})})};var ee=(e=>(e[e.SignInInProgress=1]="SignInInProgress",e[e.Success=2]="Success",e[e.Failure=3]="Failure",e[e.Selection=4]="Selection",e[e.Enroll=5]="Enroll",e))(ee||{});const me=function(e){const d=te(),[o,t]=s.useState(1),u=U(O),[b,f]=Y(),r=Q(),[c,a]=s.useState(""),[T,C]=s.useState([]),{onSignInSuccess:P,onSignInError:_}=e,l=s.useRef(_).current,I=s.useRef(P).current,F=s.useCallback(async()=>{try{const i=await J();if(!r.current)return;switch(i.result){case"auth":let h=[];i.devices.forEach(m=>h.push({id:m.device,name:m.display_name,methods:m.capabilities})),C(h),t(4);break;case"allow":l(new Error("Device selection was bypassed by Duo policy")),t(2);break;case"deny":l(new Error("Device selection was denied by Duo policy")),t(3);break;case"enroll":l(new Error("No compatible device found")),i.enroll_url&&e.duoSelfEnrollment&&a(i.enroll_url),t(5);break}}catch(i){if(!r.current)return;console.error(i),l(new Error("There was an issue fetching Duo device(s)"))}},[e.duoSelfEnrollment,r,l]),D=s.useCallback(async()=>{if(e.authenticationLevel!==k.TwoFactor)try{t(1);const i=await z(u,b,f);if(!r.current)return;if(i&&i.result==="auth"){let h=[];i.devices.forEach(m=>h.push({id:m.device,name:m.display_name,methods:m.capabilities})),C(h),t(4);return}if(i&&i.result==="enroll"){l(new Error("No compatible device found")),i.enroll_url&&e.duoSelfEnrollment&&a(i.enroll_url),t(5);return}if(i&&i.result==="deny"){l(new Error("Device selection was denied by Duo policy")),t(3);return}t(2),setTimeout(()=>{r.current&&I(i?i.redirect:void 0)},1500)}catch(i){if(!r.current||o!==1)return;console.error(i),l(new Error("There was an issue completing sign in process")),t(3)}},[e.authenticationLevel,e.duoSelfEnrollment,u,b,f,r,l,I,o]),p=s.useCallback(async function(i){try{await K(i),e.registered?t(1):(t(1),e.onSelectionClick())}catch(h){console.error(h),l(new Error("There was an issue updating preferred Duo device"))}},[l,e]),L=s.useCallback(i=>{p({device:i.id,method:i.method})},[p]);if(s.useEffect(()=>{e.authenticationLevel>=k.TwoFactor&&t(2)},[e.authenticationLevel,t]),s.useEffect(()=>{o===1&&D()},[D,o]),o===4)return n.jsx(V,{devices:T,onBack:()=>t(1),onSelect:L});let S;switch(o){case 1:S=n.jsx(j,{width:64,height:64,animated:!0});break;case 2:S=n.jsx(W,{});break;case 3:S=n.jsx(H,{})}let g=x.METHOD;return e.authenticationLevel===k.TwoFactor?g=x.ALREADY_AUTHENTICATED:o===5&&(g=x.NOT_REGISTERED),n.jsxs(q,{id:e.id,title:"Push Notification",explanation:"A notification has been sent to your smartphone",duoSelfEnrollment:c?e.duoSelfEnrollment:!1,registered:e.registered,state:g,onSelectClick:F,onRegisterClick:()=>window.open(c,"_blank"),children:[n.jsx("div",{className:d.icon,children:S}),n.jsx("div",{className:o!==3?"hidden":"",children:n.jsx(w,{color:"secondary",onClick:D,children:"Retry"})})]})},te=E(e=>({icon:{width:"64px",height:"64px",display:"inline-block"}}));export{ee as State,me as default};
