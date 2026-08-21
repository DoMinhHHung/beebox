package httpapi

const hostedHTML = `<!doctype html>
<html lang="{{LANG}}" data-theme="{{THEME}}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="csrf-token" content="{{CSRF}}">
  <title>BeeBox</title>
  <link rel="stylesheet" href="/auth/app.css">
</head>
<body>
  <a class="skip" href="#main" data-i18n="skip">Skip to content</a>
  <header class="shell header">
    <div><strong>BeeBox</strong><span class="muted" data-i18n="subtitle">Hosted authentication</span></div>
    <div class="toolbar">
      <label><span data-i18n="language">Language</span>
        <select id="language"><option value="en">English</option><option value="vi">Tiếng Việt</option></select>
      </label>
      <label><span data-i18n="theme">Theme</span>
        <select id="theme"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select>
      </label>
    </div>
  </header>

  <main id="main" class="shell stack">
    <section class="card" aria-labelledby="app-title">
      <h1 id="app-title" data-i18n="connect">Connect application</h1>
      <p class="muted" data-i18n="connectHelp">Use the application's BeeBox publishable key. Nothing is stored in browser storage.</p>
      <label>Publishable key<input id="publishable-key" autocomplete="off" spellcheck="false"></label>
      <label data-i18n-label="accessToken">Access token<input id="access-token" type="password" autocomplete="off" spellcheck="false"></label>
      <label data-i18n-label="reverification">Reverification grant<input id="reverification" type="password" autocomplete="off" spellcheck="false"></label>
    </section>

    <section class="card" aria-labelledby="primary-title">
      <h2 id="primary-title" data-i18n="primary">Sign up and sign in</h2>
      <div class="grid">
        <form class="api-form" data-path="/v1/sign-ups" data-method="POST" data-idempotency="true">
          <h3 data-i18n="signup">Email + password sign up</h3>
          <label>Email<input name="email" type="email" autocomplete="email" required></label>
          <label data-i18n-label="password">Password<input name="password" type="password" autocomplete="new-password" required></label>
          <button data-i18n="submit">Submit</button>
        </form>
        <form class="api-form" data-path="/v1/sign-ins" data-method="POST">
          <h3 data-i18n="passwordSignin">Password sign in</h3>
          <label>Email<input name="email" type="email" autocomplete="email" required></label>
          <label data-i18n-label="password">Password<input name="password" type="password" autocomplete="current-password" required></label>
          <button data-i18n="signin">Sign in</button>
        </form>
        <form class="api-form" data-path="/v1/sign-ins/email-otp" data-method="POST">
          <h3 data-i18n="emailOtp">Email OTP</h3>
          <label>Email<input name="email" type="email" autocomplete="email" required></label>
          <button data-i18n="sendCode">Send code</button>
        </form>
        <form class="api-form" data-path="/v1/sign-ins/email-otp/confirm" data-method="POST">
          <h3 data-i18n="emailOtpConfirm">Confirm email OTP</h3>
          <label>Email<input name="email" type="email" autocomplete="email" required></label>
          <label data-i18n-label="code">Code<input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
          <button data-i18n="confirm">Confirm</button>
        </form>
        <form class="api-form" data-path="/v1/sign-ins/email-link" data-method="POST">
          <h3 data-i18n="emailLink">Email sign-in link</h3>
          <label>Email<input name="email" type="email" autocomplete="email" required></label>
          <label data-i18n-label="returnUrl">Return URL<input name="completion_url" type="url" required></label>
          <button data-i18n="sendLink">Send link</button>
        </form>
        <form class="api-form" data-path="/v1/sign-ups/phone" data-method="POST">
          <h3 data-i18n="phoneSignup">Phone sign up</h3>
          <label data-i18n-label="phone">Phone<input name="phone" autocomplete="tel" placeholder="+84901234567" required></label>
          <button data-i18n="sendCode">Send code</button>
        </form>
        <form class="api-form" data-path="/v1/sign-ups/phone/confirm" data-method="POST">
          <h3 data-i18n="phoneSignupConfirm">Confirm phone sign up</h3>
          <label data-i18n-label="phone">Phone<input name="phone" autocomplete="tel" required></label>
          <label data-i18n-label="code">Code<input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
          <button data-i18n="confirm">Confirm</button>
        </form>
        <form class="api-form" data-path="/v1/sign-ins/phone-otp" data-method="POST">
          <h3 data-i18n="phoneSignin">Phone OTP sign in</h3>
          <label data-i18n-label="phone">Phone<input name="phone" autocomplete="tel" required></label>
          <button data-i18n="sendCode">Send code</button>
        </form>
        <form class="api-form" data-path="/v1/sign-ins/phone-otp/confirm" data-method="POST">
          <h3 data-i18n="phoneSigninConfirm">Confirm phone OTP</h3>
          <label data-i18n-label="phone">Phone<input name="phone" autocomplete="tel" required></label>
          <label data-i18n-label="code">Code<input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
          <button data-i18n="confirm">Confirm</button>
        </form>
      </div>
    </section>

    <section id="mfa-card" class="card" aria-labelledby="mfa-title">
      <h2 id="mfa-title" data-i18n="mfa">Multi-factor authentication</h2>
      <p class="muted" data-i18n="mfaHelp">Pending MFA authority is kept only in memory or a Secure HttpOnly hosted cookie.</p>
      <form id="mfa-form">
        <label data-i18n-label="method">Method<select id="mfa-method"><option value="totp">TOTP</option><option value="recovery_code">Recovery code</option></select></label>
        <label data-i18n-label="code">Code<input id="mfa-code" autocomplete="one-time-code" required></label>
        <button data-i18n="completeMfa">Complete MFA</button>
      </form>
    </section>

    <section class="card" aria-labelledby="passkey-title">
      <h2 id="passkey-title" data-i18n="passkeys">Passkeys</h2>
      <div class="actions">
        <button id="passkey-signin" data-i18n="passkeySignin">Sign in with passkey</button>
        <button id="passkey-register" data-i18n="passkeyRegister">Register passkey</button>
        <button class="simple-call" data-path="/v1/passkeys" data-method="GET" data-i18n="listPasskeys">List passkeys</button>
      </div>
      <form id="passkey-remove-form"><label data-i18n-label="passkeyId">Passkey ID<input id="passkey-remove-id" required></label><button data-i18n="remove">Remove</button></form>
    </section>

    <section class="card" aria-labelledby="social-title">
      <h2 id="social-title" data-i18n="social">Social sign in</h2>
      <p class="muted" data-i18n="socialHelp">Social authorization uses BeeBox's existing PKCE-bound headless flow and the application's exact redirect allowlist.</p>
      <form id="social-form">
        <label data-i18n-label="provider">Provider<select id="social-provider"><option value="google">Google</option><option value="github">GitHub</option><option value="microsoft">Microsoft</option></select></label>
        <label data-i18n-label="returnUrl">Return URL<input id="social-return" type="url" required></label>
        <button data-i18n="continueSocial">Continue</button>
      </form>
    </section>

    <section class="card" aria-labelledby="account-title">
      <h2 id="account-title" data-i18n="account">Account and profile</h2>
      <div class="actions">
        <button class="simple-call" data-path="/v1/profile" data-method="GET" data-i18n="loadProfile">Load profile</button>
        <button class="simple-call" data-path="/v1/identifiers/emails" data-method="GET" data-i18n="listEmails">List emails</button>
        <button class="simple-call" data-path="/v1/identifiers/phones" data-method="GET" data-i18n="listPhones">List phones</button>
      </div>
      <div class="grid">
        <form class="api-form" data-path="/v1/profile" data-method="PATCH">
          <h3 data-i18n="updateProfile">Update profile</h3>
          <label data-i18n-label="displayName">Display name<input name="display_name"></label>
          <label data-i18n-label="givenName">Given name<input name="given_name"></label>
          <label data-i18n-label="familyName">Family name<input name="family_name"></label>
          <label>Locale<input name="locale" placeholder="en"></label>
          <button data-i18n="save">Save</button>
        </form>
        <form class="api-form" data-path="/v1/identifiers/emails" data-method="POST">
          <h3 data-i18n="addEmail">Add email</h3><label>Email<input name="email" type="email" required></label><button data-i18n="add">Add</button>
        </form>
        <form class="api-form" data-path="/v1/identifiers/phones" data-method="POST">
          <h3 data-i18n="addPhone">Add phone</h3><label data-i18n-label="phone">Phone<input name="phone" required></label><button data-i18n="add">Add</button>
        </form>
      </div>
      <form id="identifier-action-form">
        <label data-i18n-label="identifierType">Type<select id="identifier-type"><option value="emails">Email</option><option value="phones">Phone</option></select></label>
        <label data-i18n-label="identifierId">Identifier ID<input id="identifier-id" required></label>
        <label data-i18n-label="action">Action<select id="identifier-action"><option value="verify">Request verification</option><option value="primary">Set primary</option><option value="delete">Remove</option></select></label>
        <label data-i18n-label="code">Verification code<input id="identifier-code" autocomplete="one-time-code"></label>
        <button data-i18n="submit">Submit</button>
      </form>
    </section>

    <section class="card" aria-labelledby="security-title">
      <h2 id="security-title" data-i18n="security">Security factors</h2>
      <div class="actions">
        <button class="simple-call" data-path="/v1/mfa/totp" data-method="GET" data-i18n="totpState">TOTP state</button>
        <button class="simple-call" data-path="/v1/mfa/totp/enrollments" data-method="POST" data-i18n="startTotp">Start TOTP enrollment</button>
        <button class="simple-call" data-path="/v1/mfa/recovery-codes" data-method="GET" data-i18n="recoveryState">Recovery-code state</button>
        <button class="simple-call" data-path="/v1/mfa/recovery-codes/regenerate" data-method="POST" data-i18n="regenerateRecovery">Regenerate recovery codes</button>
      </div>
      <form class="api-form" data-path="/v1/mfa/totp/enrollments/confirm" data-method="POST">
        <label data-i18n-label="enrollmentId">Enrollment ID<input name="enrollment_id" required></label>
        <label data-i18n-label="code">TOTP code<input name="code" autocomplete="one-time-code" required></label>
        <button data-i18n="confirm">Confirm</button>
      </form>
    </section>

    <section class="card" aria-labelledby="sessions-title">
      <h2 id="sessions-title" data-i18n="sessions">Sessions</h2>
      <div class="actions">
        <button class="simple-call" data-path="/v1/sessions" data-method="GET" data-i18n="listSessions">List sessions</button>
        <button class="simple-call" data-path="/v1/sessions/revoke-others" data-method="POST" data-i18n="revokeOthers">Revoke other sessions</button>
        <button class="simple-call" data-path="/v1/sessions/sign-out-everywhere" data-method="POST" data-i18n="signoutEverywhere">Sign out everywhere</button>
      </div>
      <form id="revoke-session-form"><label data-i18n-label="sessionId">Session ID<input id="revoke-session-id" required></label><button data-i18n="revoke">Revoke</button></form>
    </section>

    <section class="card" aria-live="polite" aria-labelledby="result-title">
      <h2 id="result-title" data-i18n="result">Result</h2>
      <p id="status" class="status"></p>
      <a id="continue-link" class="button hidden" rel="noreferrer" data-i18n="continue">Continue</a>
      <pre id="result"></pre>
    </section>
  </main>
  <script src="/auth/app.js" defer></script>
</body>
</html>`

const hostedCSS = `
:root{color-scheme:light dark;--bg:#f7f7f8;--panel:#fff;--text:#171717;--muted:#666;--border:#d8d8dc;--focus:#2457d6;--button:#1f4fc4;--buttonText:#fff}
html[data-theme="dark"]{color-scheme:dark;--bg:#151517;--panel:#202024;--text:#f4f4f5;--muted:#b2b2b7;--border:#3b3b42;--focus:#8fb0ff;--button:#7296f5;--buttonText:#101014}
html[data-theme="system"]{color-scheme:light dark}
@media(prefers-color-scheme:dark){html[data-theme="system"]{--bg:#151517;--panel:#202024;--text:#f4f4f5;--muted:#b2b2b7;--border:#3b3b42;--focus:#8fb0ff;--button:#7296f5;--buttonText:#101014}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.shell{width:min(1120px,calc(100% - 32px));margin-inline:auto}.header{display:flex;justify-content:space-between;gap:24px;align-items:center;padding:22px 0}.header strong{font-size:1.4rem;margin-right:12px}.toolbar,.actions{display:flex;flex-wrap:wrap;gap:12px;align-items:end}.stack{display:grid;gap:18px;padding-bottom:48px}.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}form{display:grid;gap:10px;margin:12px 0}label{display:grid;gap:5px;font-weight:600}input,select,button,.button{min-height:42px;border-radius:8px;border:1px solid var(--border);font:inherit}input,select{padding:8px 10px;background:var(--panel);color:var(--text)}button,.button{padding:9px 14px;background:var(--button);color:var(--buttonText);font-weight:700;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}button:focus-visible,input:focus-visible,select:focus-visible,.button:focus-visible{outline:3px solid var(--focus);outline-offset:2px}.muted{color:var(--muted);font-weight:400}.status{font-weight:700}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;min-height:54px}.hidden{display:none}.skip{position:absolute;left:-9999px;top:8px;background:var(--panel);padding:8px}.skip:focus{left:8px;z-index:10}@media(max-width:700px){.header{align-items:flex-start;flex-direction:column}.shell{width:min(100% - 20px,1120px)}}
`

const hostedJS = `
(function(){
"use strict";
var csrf=document.querySelector('meta[name="csrf-token"]').content;
var root=document.documentElement;
var state={access:"",pending:"",emailLinkMFA:false,socialVerifier:""};
var result=document.getElementById("result");
var status=document.getElementById("status");
var continueLink=document.getElementById("continue-link");
var pkInput=document.getElementById("publishable-key");
var accessInput=document.getElementById("access-token");
var reverifyInput=document.getElementById("reverification");
var strings={
 en:{skip:"Skip to content",subtitle:"Hosted authentication",language:"Language",theme:"Theme",connect:"Connect application",connectHelp:"Use the application's BeeBox publishable key. Nothing is stored in browser storage.",primary:"Sign up and sign in",signup:"Email + password sign up",password:"Password",passwordSignin:"Password sign in",submit:"Submit",signin:"Sign in",emailOtp:"Email OTP",emailOtpConfirm:"Confirm email OTP",sendCode:"Send code",code:"Code",confirm:"Confirm",emailLink:"Email sign-in link",returnUrl:"Return URL",sendLink:"Send link",phoneSignup:"Phone sign up",phoneSignupConfirm:"Confirm phone sign up",phoneSignin:"Phone OTP sign in",phoneSigninConfirm:"Confirm phone OTP",phone:"Phone",mfa:"Multi-factor authentication",mfaHelp:"Pending MFA authority is kept only in memory or a Secure HttpOnly hosted cookie.",method:"Method",completeMfa:"Complete MFA",passkeys:"Passkeys",passkeySignin:"Sign in with passkey",passkeyRegister:"Register passkey",listPasskeys:"List passkeys",passkeyId:"Passkey ID",remove:"Remove",social:"Social sign in",socialHelp:"Social authorization uses BeeBox's existing PKCE-bound headless flow and the application's exact redirect allowlist.",provider:"Provider",continueSocial:"Continue",account:"Account and profile",loadProfile:"Load profile",listEmails:"List emails",listPhones:"List phones",updateProfile:"Update profile",displayName:"Display name",givenName:"Given name",familyName:"Family name",save:"Save",addEmail:"Add email",addPhone:"Add phone",add:"Add",identifierType:"Type",identifierId:"Identifier ID",action:"Action",security:"Security factors",totpState:"TOTP state",startTotp:"Start TOTP enrollment",recoveryState:"Recovery-code state",regenerateRecovery:"Regenerate recovery codes",enrollmentId:"Enrollment ID",sessions:"Sessions",listSessions:"List sessions",revokeOthers:"Revoke other sessions",signoutEverywhere:"Sign out everywhere",sessionId:"Session ID",revoke:"Revoke",result:"Result",continue:"Continue",accessToken:"Access token",reverification:"Reverification grant"},
 vi:{skip:"Bỏ qua đến nội dung",subtitle:"Xác thực được lưu trữ",language:"Ngôn ngữ",theme:"Giao diện",connect:"Kết nối ứng dụng",connectHelp:"Dùng publishable key của ứng dụng BeeBox. Không lưu token vào bộ nhớ trình duyệt.",primary:"Đăng ký và đăng nhập",signup:"Đăng ký email + mật khẩu",password:"Mật khẩu",passwordSignin:"Đăng nhập bằng mật khẩu",submit:"Gửi",signin:"Đăng nhập",emailOtp:"OTP email",emailOtpConfirm:"Xác nhận OTP email",sendCode:"Gửi mã",code:"Mã",confirm:"Xác nhận",emailLink:"Liên kết đăng nhập email",returnUrl:"URL quay lại",sendLink:"Gửi liên kết",phoneSignup:"Đăng ký bằng số điện thoại",phoneSignupConfirm:"Xác nhận đăng ký điện thoại",phoneSignin:"Đăng nhập OTP điện thoại",phoneSigninConfirm:"Xác nhận OTP điện thoại",phone:"Số điện thoại",mfa:"Xác thực đa yếu tố",mfaHelp:"Quyền MFA tạm thời chỉ ở bộ nhớ hoặc cookie Secure HttpOnly.",method:"Phương thức",completeMfa:"Hoàn tất MFA",passkeys:"Passkey",passkeySignin:"Đăng nhập bằng passkey",passkeyRegister:"Đăng ký passkey",listPasskeys:"Danh sách passkey",passkeyId:"ID passkey",remove:"Xóa",social:"Đăng nhập mạng xã hội",socialHelp:"Luồng social dùng PKCE headless hiện có và redirect allowlist chính xác của ứng dụng.",provider:"Nhà cung cấp",continueSocial:"Tiếp tục",account:"Tài khoản và hồ sơ",loadProfile:"Tải hồ sơ",listEmails:"Danh sách email",listPhones:"Danh sách điện thoại",updateProfile:"Cập nhật hồ sơ",displayName:"Tên hiển thị",givenName:"Tên",familyName:"Họ",save:"Lưu",addEmail:"Thêm email",addPhone:"Thêm điện thoại",add:"Thêm",identifierType:"Loại",identifierId:"ID định danh",action:"Hành động",security:"Yếu tố bảo mật",totpState:"Trạng thái TOTP",startTotp:"Bắt đầu TOTP",recoveryState:"Trạng thái mã khôi phục",regenerateRecovery:"Tạo lại mã khôi phục",enrollmentId:"ID đăng ký",sessions:"Phiên đăng nhập",listSessions:"Danh sách phiên",revokeOthers:"Thu hồi phiên khác",signoutEverywhere:"Đăng xuất mọi nơi",sessionId:"ID phiên",revoke:"Thu hồi",result:"Kết quả",continue:"Tiếp tục",accessToken:"Access token",reverification:"Reverification grant"}
};
function locale(){return root.lang==="vi"?"vi":"en"}
function translate(){var table=strings[locale()];document.querySelectorAll("[data-i18n]").forEach(function(el){var v=table[el.dataset.i18n];if(v)el.textContent=v});document.querySelectorAll("[data-i18n-label]").forEach(function(el){var v=table[el.dataset.i18nLabel];if(v&&el.firstChild)el.firstChild.textContent=v})}
function show(data,ok){status.textContent=ok?(locale()==="vi"?"Thành công":"Success"):(locale()==="vi"?"Không thể hoàn tất yêu cầu":"Request failed");result.textContent=JSON.stringify(data,null,2);continueLink.classList.add("hidden");if(data&&data.completion_url){continueLink.href=data.completion_url;continueLink.classList.remove("hidden")}}
function headers(extra){var h={"Content-Type":"application/json","X-BeeBox-CSRF":csrf};var pk=pkInput.value.trim();if(pk)h["X-BeeBox-Publishable-Key"]=pk;var access=state.access||accessInput.value.trim();if(access)h.Authorization="Bearer "+access;var rev=reverifyInput.value.trim();if(rev)h["X-BeeBox-Reverification"]=rev;if(extra)Object.keys(extra).forEach(function(k){h[k]=extra[k]});return h}
async function api(path,method,body,extra){var options={method:method||"GET",headers:headers(extra),credentials:"same-origin"};if(options.method!=="GET"&&options.method!=="HEAD")options.body=JSON.stringify(body||{});var response=await fetch("/auth/api"+path,options);var data={};try{data=await response.json()}catch(_){data={status:response.status}};if(data.access_token){state.access=data.access_token;accessInput.value=data.access_token}if(data.pending_mfa_token){state.pending=data.pending_mfa_token}show(data,response.ok);return {response:response,data:data}}
function formBody(form){var out={};new FormData(form).forEach(function(v,k){if(v!=="")out[k]=v});return out}
document.querySelectorAll(".api-form").forEach(function(form){form.addEventListener("submit",async function(e){e.preventDefault();var extra={};if(form.dataset.idempotency==="true")extra["Idempotency-Key"]=crypto.randomUUID();try{await api(form.dataset.path,form.dataset.method,formBody(form),extra)}catch(err){show({error:"network_error"},false)}})})
document.querySelectorAll(".simple-call").forEach(function(button){button.addEventListener("click",async function(){try{await api(button.dataset.path,button.dataset.method,{},null)}catch(_){show({error:"network_error"},false)}})})
document.getElementById("mfa-form").addEventListener("submit",async function(e){e.preventDefault();var code=document.getElementById("mfa-code").value;var method=document.getElementById("mfa-method").value;try{if(state.emailLinkMFA){var special=method==="recovery_code"?"/email-link/mfa/recovery":"/email-link/mfa/totp";var r=await api(special,"POST",{code:code},null);if(r.response.ok&&r.data.access_token){state.emailLinkMFA=false}}else{var path=method==="recovery_code"?"/v1/mfa/recovery-codes/complete":"/v1/mfa/totp/complete";await api(path,"POST",{pending_mfa_token:state.pending,code:code},null)}}catch(_){show({error:"network_error"},false)}})
document.getElementById("identifier-action-form").addEventListener("submit",async function(e){e.preventDefault();var type=document.getElementById("identifier-type").value;var id=document.getElementById("identifier-id").value.trim();var action=document.getElementById("identifier-action").value;var code=document.getElementById("identifier-code").value.trim();var path="/v1/identifiers/"+type+"/"+encodeURIComponent(id);var method="POST",body={};if(action==="verify"){path+="/verification";if(code){path+="/confirm";body.code=code}}else if(action==="primary"){path+="/primary"}else{method="DELETE"}await api(path,method,body,null)})
document.getElementById("revoke-session-form").addEventListener("submit",async function(e){e.preventDefault();var id=document.getElementById("revoke-session-id").value.trim();await api("/v1/sessions/"+encodeURIComponent(id)+"/revoke","POST",{},null)})
function b64url(buf){return btoa(String.fromCharCode.apply(null,new Uint8Array(buf))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
async function sha256(value){return b64url(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value)))}
document.getElementById("social-form").addEventListener("submit",async function(e){e.preventDefault();var raw=new Uint8Array(32);crypto.getRandomValues(raw);state.socialVerifier=b64url(raw);var challenge=await sha256(state.socialVerifier);var body={provider:document.getElementById("social-provider").value,redirect_url:document.getElementById("social-return").value,code_challenge:challenge,code_challenge_method:"S256"};var r=await api("/v1/social-auth/attempts","POST",body,null);if(r.response.ok&&r.data.authorization_url)location.assign(r.data.authorization_url)})
function decodeB64url(v){var s=v.replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";var bin=atob(s),out=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)out[i]=bin.charCodeAt(i);return out.buffer}
function normalizePublicKey(options){if(options.challenge)options.challenge=decodeB64url(options.challenge);if(options.user&&options.user.id)options.user.id=decodeB64url(options.user.id);if(options.allowCredentials)options.allowCredentials.forEach(function(c){c.id=decodeB64url(c.id)});if(options.excludeCredentials)options.excludeCredentials.forEach(function(c){c.id=decodeB64url(c.id)});return options}
function credentialJSON(cred){var response={clientDataJSON:b64url(cred.response.clientDataJSON)};if(cred.response.attestationObject)response.attestationObject=b64url(cred.response.attestationObject);if(cred.response.authenticatorData)response.authenticatorData=b64url(cred.response.authenticatorData);if(cred.response.signature)response.signature=b64url(cred.response.signature);if(cred.response.userHandle)response.userHandle=b64url(cred.response.userHandle);return {id:cred.id,rawId:b64url(cred.rawId),type:cred.type,response:response,clientExtensionResults:cred.getClientExtensionResults()}}
document.getElementById("passkey-signin").addEventListener("click",async function(){try{var begin=await api("/v1/passkeys/authentication/attempts","POST",{},null);if(!begin.response.ok)return;var opts=begin.data.public_key||begin.data.options||begin.data;var cred=await navigator.credentials.get({publicKey:normalizePublicKey(opts)});await api("/v1/passkeys/authentication/complete","POST",{attempt_id:begin.data.attempt_id,credential:credentialJSON(cred)},null)}catch(_){show({error:"passkey_failed"},false)}})
document.getElementById("passkey-register").addEventListener("click",async function(){try{var begin=await api("/v1/passkeys/registration/attempts","POST",{},null);if(!begin.response.ok)return;var opts=begin.data.public_key||begin.data.options||begin.data;var cred=await navigator.credentials.create({publicKey:normalizePublicKey(opts)});await api("/v1/passkeys/registration/complete","POST",{attempt_id:begin.data.attempt_id,credential:credentialJSON(cred)},null)}catch(_){show({error:"passkey_failed"},false)}})
document.getElementById("passkey-remove-form").addEventListener("submit",async function(e){e.preventDefault();var id=document.getElementById("passkey-remove-id").value.trim();await api("/v1/passkeys/"+encodeURIComponent(id),"DELETE",{},null)})
document.getElementById("language").value=locale();document.getElementById("language").addEventListener("change",function(e){root.lang=e.target.value==="vi"?"vi":"en";translate()});document.getElementById("theme").value=root.dataset.theme;document.getElementById("theme").addEventListener("change",function(e){var v=e.target.value;root.dataset.theme=(v==="light"||v==="dark")?v:"system"});translate();
async function consumeEmailLink(){if(location.pathname!=="/auth/email-link")return;var params=new URLSearchParams(location.search);var challenge=params.get("challenge")||"";var pk=params.get("pk")||"";var fragment=new URLSearchParams(location.hash.slice(1));var secret=fragment.get("secret")||"";history.replaceState(null,"",location.pathname+location.search);pkInput.value=pk;if(!challenge||!pk||!secret){show({error:"invalid_email_link"},false);return}try{var response=await fetch("/auth/api/email-link/confirm",{method:"POST",credentials:"same-origin",headers:headers(null),body:JSON.stringify({challenge_id:challenge,secret:secret})});var data={};try{data=await response.json()}catch(_){data={}};if(data.access_token){state.access=data.access_token;accessInput.value=data.access_token}if(data.status==="mfa_required")state.emailLinkMFA=true;show(data,response.ok)}catch(_){show({error:"network_error"},false)}}
consumeEmailLink();
})();
`
