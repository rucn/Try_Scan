package burp;

import burp.common.CustomScanIssue;
import burp.common.ScanJudge;
import burp.common.YamlReader;
import burp.scan.FastJsonScan;
import burp.scan.Log4jScan;
import burp.scan.NacosScan;
import burp.scan.SpringSpiderScan;

import java.awt.*;
import java.io.IOException;
import java.io.PrintWriter;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender,IScannerCheck,ITab{

    static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;

    List<IScanIssue> issues = new ArrayList();
    ScanJudge scanJudge;

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Try_Scan");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("===================================");
        stdout.println("     Try_Scan Load the success     ");
        stdout.println("          VERSION: 0.0.1           ");
        stdout.println("          author: Xiaonanfei       ");
        stdout.println("     Fastjson/Log4j2/api/Nacos     ");
        stdout.println("===================================");
        callbacks.registerScannerCheck(this);
        scanJudge = new ScanJudge(callbacks, stdout);
    }
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<String> resheaders = helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders();
        IRequestInfo iRequestInfo = helpers.analyzeRequest(baseRequestResponse);
        URL url = iRequestInfo.getUrl();
        if (!YamlReader.getInstance(callbacks).getBoolean("isStart")) {
            stdout.println("插件关闭使用");
            return null;
        }
        if (scanJudge.isBlackdomain(url.getAuthority())) {
            stdout.println("检查到黑名单域名，跳过目标: " + url);
            return null;
        }
        if (scanJudge.isBlackheader(resheaders)) {
            stdout.println("检查到非java网站特征，跳过目标: " + url);
            return null;
        }
        if (scanJudge.isBlackSuffix(url.getPath())) {
            stdout.println("检查到后缀黑名单，跳过目标: " + url);
            return null;
        }

        if(YamlReader.getInstance(callbacks).getBoolean("scanModule.SpringSpiderScan.isStart")){
            List<IHttpRequestResponse>  SpringSpiderScanResults= SpringSpiderScan.ScanMain(baseRequestResponse,callbacks,helpers, stdout);
            for(IHttpRequestResponse result:SpringSpiderScanResults){
                if(result != null){
                    String payload = helpers.analyzeRequest(result).getUrl().getPath();
                    if(payload.endsWith("/env")){
                        Addissuse(result,"Springboot actuator Foud!",payload);
                    } else if (payload.contains("api-docs") || payload.contains("swagger.")) {
                        Addissuse(result,"Api-Docs Foud!",payload);
                    } else if (payload.contains("druid")) {
                        Addissuse(result,"Druid-monitor-unauth  Foud!",payload);
                    }
                }
            }
        }

        if(YamlReader.getInstance(callbacks).getBoolean("scanModule.Log4jScan.isStart")){
            List<Object> Log4jSuccess = null;
            try {
                Log4jSuccess = Log4jScan.ScanMain(baseRequestResponse, callbacks, helpers, stdout);
            } catch (IOException e) {
                stderr.println(e);
            } catch (InterruptedException e) {
                stderr.println(e);
            }
            if(Log4jSuccess != null){
                Addissuse((IHttpRequestResponse) Log4jSuccess.get(0),"Log4j Rce Foud!", (String) Log4jSuccess.get(1));
            }
        }

        if(YamlReader.getInstance(callbacks).getBoolean("scanModule.FastJsonScan.isStart")){
            List<Object> FastjsonSuccess = null;
            try {
                FastjsonSuccess = FastJsonScan.ScanMain(baseRequestResponse, callbacks, helpers, stdout);
            } catch (IOException e) {
                stderr.println(e);
            } catch (InterruptedException e) {
                stderr.println(e);
            }
            if(FastjsonSuccess != null){
                Addissuse((IHttpRequestResponse) FastjsonSuccess.get(0),"Fastjson Rce Foud!", (String) FastjsonSuccess.get(1));
            }
        }


// nacos检测  判断条件均为nacos存在再进行判断减少扫描量
        if (YamlReader.getInstance(callbacks).getBoolean("scanModule.NacosScan.isStart")) {
            List<IHttpRequestResponse> nacosScanResults = NacosScan.ScanMain(baseRequestResponse, callbacks, helpers, stdout);
            if (!nacosScanResults.isEmpty()) {
                for (IHttpRequestResponse result : nacosScanResults) {
                    if (result != null) {
                        String payload = helpers.analyzeRequest(result).getUrl().getPath();

                        if (payload.contains("nacos") || payload.contains("/")) {
                            Addissuse(result, "Nacos Found!", payload);

                            stdout.println("-------弱口令检测-------");
                            IHttpRequestResponse weakPassResponse = NacosScan.checkWeekPass(result, helpers.analyzeRequest(result).getHeaders(), payload);
                            if (weakPassResponse != null) {
                                // 弱口令检测成功，记录该漏洞
                                stdout.println("[NacosScan]弱口令 " + payload);
                                Addissuse(weakPassResponse, "Weak Password Found!", payload);
                            }

                            stdout.println("----------未授权漏洞检测---------");
                            IHttpRequestResponse unauthScan = NacosScan.unauthScan(result, helpers.analyzeRequest(result).getHeaders(), payload);
                            if (unauthScan != null) {
                                stdout.println("未授权检测 " + payload);
                                Addissuse(unauthScan, "Unauth Found!", payload);
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }


    @Override
    public String getTabCaption() {
        return null;
    }

    @Override
    public Component getUiComponent() {
        return null;
    }
    public void Addissuse(IHttpRequestResponse reqres, String vulname,String payload){
        URL url = helpers.analyzeRequest(reqres).getUrl();
        stdout.println(url + " " + vulname + " !存在");
        callbacks.addScanIssue(new CustomScanIssue(reqres.getHttpService(), url, new IHttpRequestResponse[]{reqres}, vulname, "payload: " + payload, "High"));
    }
}