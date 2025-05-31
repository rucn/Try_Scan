package burp.scan;

import burp.*;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public class NacosScan {
    // 扫描过的 baseurl 集合
    private static final Set<String> scannedBaseUrls = Collections.synchronizedSet(new HashSet<>());

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static PrintWriter stdout;

    // Nacos 路径和特征关键字
    private static final List<String> NacosPaths = Arrays.asList("/", "/nacos");
    private static final List<String> NacosKeywords = Arrays.asList("nacos", "Nacos");

    // 主扫描入口
    public synchronized static List<IHttpRequestResponse> ScanMain(
            IHttpRequestResponse baseRequestResponse,
            IBurpExtenderCallbacks cb,
            IExtensionHelpers hlp,
            PrintWriter out) {

        callbacks = cb;
        helpers = hlp;
        stdout = out;

        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        String baseurl = url.getProtocol() + "://" + url.getAuthority();

        stdout.println("[NacosScan] 开始扫描 " + baseurl);

        List<IHttpRequestResponse> foundList = new ArrayList<>();

        if (scannedBaseUrls.contains(baseurl)) {
            stdout.println("[NacosScan] 已扫描过，跳过: " + baseurl);
            return foundList;
        }

        List<String> scanUrls = urlCheck(baseurl);

        IHttpRequestResponse result = isExistNacos(scanUrls, helpers.analyzeRequest(baseRequestResponse).getHeaders(), baseRequestResponse, baseurl);
        if (result != null) {
            foundList.add(result);
            scannedBaseUrls.add(baseurl);
        }
        return foundList;
    }

    // 简单 url 列表生成
    private static List<String> urlCheck(String baseurl) {
        List<String> list = new ArrayList<>();
        if (baseurl.endsWith("/")) {
            baseurl = baseurl.substring(0, baseurl.length() - 1);
        }
        list.add(baseurl);
        return list;
    }

    // 判断 Nacos 是否存在
    public synchronized static IHttpRequestResponse isExistNacos(List<String> scanUrls,
                                                                 List<String> headers,
                                                                 IHttpRequestResponse baseRequestResponse,
                                                                 String baseurl) {
        for (String scanUrl : scanUrls) {
            for (String nacosPath : NacosPaths) {
                String relativePath = scanUrl.equals(baseurl) ? nacosPath : scanUrl.replace(baseurl, "") + nacosPath;
                relativePath = relativePath.replaceAll("//", "/");  // 防止出现双斜杠

                stdout.println("[NacosScan] 开始扫描路径: " + relativePath);

                try {
                    URL normalizedUrl = new URL(baseurl + relativePath);
                    String normalizedPath = normalizedUrl.getPath();
                    if (!normalizedPath.startsWith("/")) {
                        normalizedPath = "/" + normalizedPath;
                    }
                    relativePath = normalizedPath;
                } catch (Exception e) {
                    stdout.println("URLERROR");
                }


                String requestLine = "GET " + relativePath + " HTTP/1.1";
                stdout.println("[NacosScan] 请求行: " + requestLine);

                // 设置请求行
                headers.set(0, requestLine);
                byte[] requestBytes = helpers.buildHttpMessage(headers, null);

                // 发送请求
                IHttpRequestResponse response = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), requestBytes);

                //获取响应包
                byte[] fullResponse = response.getResponse();
                IResponseInfo responseInfo = helpers.analyzeResponse(fullResponse);
                List<String> responseHeaders = responseInfo.getHeaders();
                StringBuilder headersBuilder = new StringBuilder();
                for (String header : responseHeaders) {
                    headersBuilder.append(header).append("\r\n");
                }
                String responseHeadersStr = headersBuilder.toString();
                int bodyOffset = responseInfo.getBodyOffset();
                String responseBody = new String(fullResponse, bodyOffset, fullResponse.length - bodyOffset);
                int statusCode = helpers.analyzeResponse(response.getResponse()).getStatusCode();

//                stdout.println("[NacosScan] 响应状态码: " + statusCode);
                if (statusCode == 200 || statusCode == 302) {
                    for (String nacosKeyword : NacosKeywords) {
                        if (responseBody.contains(nacosKeyword) || responseHeadersStr.contains(nacosKeyword)) {
                            scannedBaseUrls.add(baseurl);
                            return response;
                        }

                    }
                }


            }
        }
        return null;
    }


    //测试弱口令
    public synchronized static IHttpRequestResponse checkWeekPass(IHttpRequestResponse baseRequestResponse,
                                                                  List<String> headers, String baseurl) {
        List<String> weakPasswords = Arrays.asList("nacos:nacos");
        List<String> weakPath = Arrays.asList("/v3/auth/user/login",
                "/nacos/v3/auth/user/login",
                "/v1/auth/user/login",
                "/nacos/v1/auth/user/login");


        for (String Path : weakPath) {
            for (String AA : weakPasswords) {
                String[] parts = AA.split(":");
                String username = parts[0];
                String password = parts[1];

                String postData = "username=" + username + "&password=" + password;

                List<String> newHeaders = new ArrayList<>();
                // 添加请求行
                newHeaders.add("POST " + Path + " HTTP/1.1");

                // 从原始headers中获取Host头
                String hostHeader = "Host: " + baseRequestResponse.getHttpService().getHost() + ":" + baseRequestResponse.getHttpService().getPort();
                newHeaders.add(hostHeader);

                // 添加必要的请求头
                newHeaders.add("Content-Type: application/x-www-form-urlencoded");
                newHeaders.add("Content-Length: " + postData.length()); // 计算正确的内容长度
                newHeaders.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36");
                newHeaders.add("Connection: keep-alive");

                stdout.println("请求头---"+newHeaders);
                byte[] requestBytes = helpers.buildHttpMessage(newHeaders, postData.getBytes());
                IHttpRequestResponse response = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), requestBytes);

                byte[] fullResponse = response.getResponse();
                IResponseInfo responseInfo = helpers.analyzeResponse(fullResponse);
                int statusCode = helpers.analyzeResponse(response.getResponse()).getStatusCode();
                String responseBody = new String(fullResponse, responseInfo.getBodyOffset(), fullResponse.length - responseInfo.getBodyOffset());

                stdout.println("状态码: " + statusCode);
                stdout.println("响应体: " + responseBody);

                if (statusCode == 200) {
                    stdout.println("响应体: " + responseBody);
                    if (responseBody.contains("accessToken")) {
                        stdout.println("[NacosScan] 弱口令检测成功: " + baseurl);
                        return response;
                    }
                }

            }
        }
        return null;
    }

    //未授权nacos测试
    public synchronized static IHttpRequestResponse unauthScan(IHttpRequestResponse baseRequestResponse,
                                                               List<String> headers, String baseurl){

        // 漏洞 POC
        List<String> PocPaths = Arrays.asList("/actuator","/nacos/actuator");
        List<String> PocKeywords = Arrays.asList("prometheus","actuator");
        for(String PocPath : PocPaths) {
            String relativePath = baseurl.endsWith("/") ? baseurl + PocPath : baseurl + "/" + PocPath;
            relativePath = relativePath.replaceAll("//", "/");

            String PocLine = "GET "+relativePath+" HTTP/1.1";
            stdout.println("检测--"+PocLine);
            headers.set(0,PocLine);
            byte[] requestBytes = helpers.buildHttpMessage(headers, null);
            IHttpRequestResponse response = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), requestBytes);

            byte[] fullResponse = response.getResponse();
            IResponseInfo responseInfo = helpers.analyzeResponse(fullResponse);
            int statusCode = helpers.analyzeResponse(response.getResponse()).getStatusCode();
            List<String> responseHeaders = responseInfo.getHeaders();
            StringBuilder headersBuilder = new StringBuilder();
            for (String header : responseHeaders) {
                headersBuilder.append(header).append("\r\n");
            }
            int bodyOffset = responseInfo.getBodyOffset();
            String responseBody = new String(fullResponse, bodyOffset, fullResponse.length - bodyOffset);
            if (statusCode == 200) {
                for (String keyword : PocKeywords) {
                    if (responseBody.contains(keyword)) {
                        return response;
                    }
                }
            }
        }

        return null;
    }
}
