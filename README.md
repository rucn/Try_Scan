# Try_Scan


## 简介

Try_Scan:  一款用于辅助渗透测试工程师日常渗透测试的Burp被动漏扫插件，修改源于开源项目https://github.com/EASY233/BpScan

##  插件功能

目前暂时只支持扫描以下漏洞，因为是在EASY233是否的基础上慢慢去进行魔改添加新功能:

- SpringSpiderScan，支持扫描Spring Actuator组件未授权访问，Swagger API 泄露，Druid Monitor 未授权访问，支持路径逐层扫描探测，支持自动Bypass路径(使用Bypass字符..;)。

- Log4jScan,对所有请求参数以及指定的header头进行Log4j Rce漏洞探测。
- FastJsonScan，对POST内容为JSON或者POST参数为JSON处进行FastJson Rce漏洞探测。
- NacosScan 探测是否存在Nacos系统，同时同步检测弱口令和未授权的接口(但是老版本的CVE暂时还没写进去，如果需要后续再扩充)

## 使用方法

下载releases压缩包,根据自已的需要修改resources中的config.yml配置文件。dnslog探测使用的是[ceye](http://ceye.io/)的在使用前请务必在resources/config.yml文件中修改domain以及token不然会影响正常的使用

http://ceye.io/ 上去生成apikey填写在中即可config.yaml

然后在Burp Extender标签页导入我们的插件即可，导入成功标志

当我们正常访问网站，网站流量经过Burp，其请求信息符合我们的扫描要求就会开启漏扫

## 注意事项

1、默认使用jdk1.8编译，若出现jdk问题插件不可用，请下载源码自行编译。

2、有时候流量过大插件扫描会比较慢，请耐心等待插件扫描结束。

3、 目前我也是刚开始接触插件这个开发代码纯堆出来的，后续会去进行修改和添加新功能争取早日将其他中间件漏洞的探测写进来。


