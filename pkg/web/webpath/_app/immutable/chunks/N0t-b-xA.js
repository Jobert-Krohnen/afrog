const e=`# Targets

## Target

To specify the scanning target, use the \`-target\` or \`-t\` command. The input can be a complete URL (e.g., \`http(s)://example.com\`) or a domain name or IP address (e.g., \`192.168.66.100\`, \`example.com\`). If the target is provided in the latter format, afrog will automatically detect the HTTP(S) protocol and fill in the correct protocol before initiating the PoC scan.

\`\`\`sh
afrog -t https://example.com
\`\`\`

## Target File

To specify a scan file, use the \`-target-file\` or \`-T\` command. Each line in the file should contain a scan target, which can be a complete URL (e.g., \`http(s)://example.com\`) or a domain/IP address (e.g., \`192.168.66.100\`, \`example.com\`). For domain/IP targets, afrog automatically detects the HTTP(S) protocol and fills in the correct protocol before conducting the PoC scan.

\`\`\`sh
afrog -T urls.txt
\`\`\`

urls.txt

\`\`\`sh
https://example.com
http://hackerone.com
...
\`\`\`

# PoCs

afrog automatically includes all PoCs within the binary program, eliminating the need to specify PoC files or paths. If you want to invoke or debug local PoCs, you can utilize the \`-poc-file\` or \`-P\` commands. To view the complete list of PoCs included in afrog, simply use the \`poc-list\` or \`-pl\` command. If you desire to examine the details of a specific PoC, employ the \`poc-detail\` or \`-pd\` command.


## PoC File

You can specify a local PoC file or folder using the \`-poc-file\` or \`-P\` command. Typically, the \`-P\` command is used for debugging local PoCs. For instance, suppose I'm working on a PoC called \`phpinfo-detect.yaml\` in the \`d:/mypocs\` folder. You can execute the following command: \`afrog -t https://example.com -P d:/mypocs/phpinfo-detect.yaml\`. Additionally, you can specify a folder: \`afrog -t https://example.com -P d:/mypocs/\`, which will scan all files with the \`.yaml\` or \`.yml\` extension in the \`mypocs\` folder.

\`\`\`sh
afrog -t https://example.com -P ./mypocs
afrog -t https://example.com -P ./mypocs/phpinfo-detect.yaml
\`\`\`

## PoC List

To view all the PoCs included in afrog, use the \`-poc-list\` or \`-pl\` command. This command will print a PoC list on the console, displaying the \`id\`, \`info.name\`, \`info.severity\`, and \`info.author\` information for each PoC. If you want to delve into the details of a specific PoC, use the \`-poc-detail\` or \`-pd\` command, followed by the desired PoC's \`id\` name.

\`\`\`sh
afrog -poc-list
afrog -pl
\`\`\`

The example output is displayed as follows:

\`\`\`sh
[CVE-2013-1965][Apache Struts2 S2-012 RCE][critical] author:xx
[CVE-2013-2251][Apache Struts 2 - DefaultActionMapper Prefixes OGNL Code Execution (S2-016)][critical] author:xx
[CVE-2014-3120][ElasticSearch v1.1.1/1.2 RCE][critical] author:xx
[CVE-2014-3704][Drupal SQL Injection][high] author:xx
[CVE-2014-6271][ShellShock - Remote Code Execution][critical] author:xx
[CVE-2015-1427][ElasticSearch - Remote Code Execution][critical] author:xx
[CVE-2015-3337][Elasticsearch CVE-2015-3337][medium] author:xx
[CVE-2015-5531][Elasticsearch CVE-2015-5531][medium] author:xx
[CVE-2015-7297][Joomla Core SQL Injection][high] author:xx
[CVE-2015-8399][Atlassian Confluence configuration files read][medium] author:xx
[CVE-2016-10134][Zabbix CVE-2016-10134][critical] author:xx
[CVE-2016-3081][Apache S2-032 Struts RCE][high] author:xx
...
\`\`\`

## PoC Detail

To view the specific content of a PoC, use the -poc-detail or -pd command. This command will print the detailed content of the PoC on the console.

\`\`\`sh
afrog -poc-detail CVE-2015-8399
afrog -pd CVE-2015-8399
\`\`\`

The example output is displayed as follows:

\`\`\`sh
id: CVE-2015-8399

info:
  name: Atlassian Confluence configuration files read
  author: whynot(https://github.com/notwhy)
  severity: medium
  verified: false

rules:
  r0
    request:
      method: GET
      path: /spaces/viewdefaultdecorator.action?decoratorName
    expression: response.status == 200 && response.body.bcontains(b"confluence-init.properties") && response.body.bcontains(b"View Default Decorator")
expression: r0()
\`\`\`

## Append PoC 

The new feature, -append-poc / -ap, allows specifying one or multiple PoC files or directories to be merged with the built-in PoC for scanning together.

\`\`\`sh
afrog -t example.com -ap ./mypocs/
afrog -t example.com -ap ./mypocs/cve/2023-xx-xx.yaml
\`\`\`

## Exclude PoC

afrog v2.7.3 introduces two new commands, they are -ep (--exclude-pocs) and -epf (--exclude-pocs-file). These two commands are mainly used to exclude PoCs from the scan. POCs to exclude can be specified comma-separated or as a list of files. Excluded PoCs are based on pattern matching. Some examples are provided below to illustrate the usage of the commands in detail.

Use the \`-ep\` command to exclude Redis, Mysql POC scans.

\`\`\`sh
afrog.exe -t 127.0.0.1 -ep redis,mysql
\`\`\`

You can also use the file list to add content to be excluded. First, create a file called \`exclude.txt\` and fill it with the following:
\`\`\`text
redis
php
cnvd
\`\`\`

Excuting an Code

\`\`\`sh
afrog.exe -t 127.0.0.1 -epf .\\exclude.txt
\`\`\`

# Output

## Output

Optional command: \`-o\`, writes the vulnerability scan results to the specified HTML file in real time. If the filename is not specified, a HTML file will be automatically created in the ./reports directory.

\`\`\`sh
afrog -t https://example.com -o result.html
\`\`\`

## Json Output

Optional command: \`-json\` \`-j\`, Save the scan results to a JSON file. The JSON file includes the following contents by default: \`target\`, \`fulltarget\`, \`id\`, and \`info\`. The info field includes the following sub-fields: \`name\`, \`author\`, \`severity\`, \`description\`, and \`reference\`. If you want to save both \`request\` and \`response\` contents, please use the [-json-all](#jsonall) command parameter.

\`\`\`sh
afrog  -t https://example.com -json result.json
afrog  -t https://example.com -j result.json
\`\`\`

::: warning
The content of the JSON file is updated in real time. However, there is an important note to keep in mind: before the scan is completed, if developers want to parse the file content, they need to add a '\`]\`' symbol to the end of the file by themselves, otherwise it will cause parsing errors. Of course, if you wait for the scan to complete before parsing the file, this issue will not occur.
:::

## JsonAll

Optional command: \`-json-all\` \`-ja\`, The only difference between the \`-json-all\` and \`-json\` commands is that \`-json-all\` writes all vulnerability results, including \`request\` and \`response\`, to a JSON file.

\`\`\`sh
afrog -t https://example.com -json-all result.json
afrog -t https://example.com -ja result.json
\`\`\`

## Disable Output Html

The "disable-output-html" command can be used to prevent the automatic generation of an HTML report, and its priority is higher than the "-o" command.

\`\`\`sh
afrog -t https://example.com -disable-output-html
afrog -t https://example.com -doh
\`\`\`

# Filters

Afrog supports two basic filters for custom execution.

1. Keywords (-s)

    Filter based on \`id\` and \`info.name\` field available in the PoCs

2. Severity (-S)

    Filter based on \`severity\` field available in the PoCs


## Keyword Filtering

Use the command \`-s keyword\` to perform a fuzzy search on all PoCs and scan the search results. Multiple keywords can be used, separated by commas. For example: \`-s weblogic,jboss\`.

\`\`\`sh
afrog -t https://example.com -s weblogic,jboss
\`\`\`

## Severity Filtering
Use the command \`-S keyword\` to scan vulnerabilities based on their severity level. Severity levels include: \`info\`, \`low\`, \`medium\`, \`high\`, and \`critical\`. For example, to only scan high and critical vulnerabilities, use the command \`-S high,critical\`.

\`\`\`sh
afrog -t https://example.com -S high,critical
\`\`\`

# Rate Limits

Afrog provides multiple rate limiting commands. The following are examples of each command along with their description.

1. Rate-Limit (-rl)

    Control the total number of request to send per seconds

2. Req-Limit-Per-Target (-rlt)

    Control the maximum number of requests per second per target (host:port)

3. Concurrency (-c)

    Control the number of PoCs to process in parallel

::: tip
Please note that the rate-limit flag should be given higher priority than the Concurrency flag, as the former determines the maximum number of requests to be sent per second, regardless of any changes made to the value of the c flag.
:::


## Rate Limit

The rate limit feature controls the overall number of requests sent per second, with a default value set to **150**.

\`\`\`sh
afrog -t https://example.com -rl 200
\`\`\`

## Concurrency

You can use this command to control the maximum number of PoCs processed in parallel, which has a default value of **25**.

\`\`\`sh
afrog -t https://example.com -c 600
\`\`\`

## Req Limit Per Target

\`req-limit-per-target\` limits the maximum number of requests per second for a single target (host:port). Setting it to \`0\` disables this limiter.

\`\`\`sh
afrog -T urls.txt -rlt 15
\`\`\`

## Per-target Presets

Afrog provides three presets to set \`req-limit-per-target\` without manual tuning. Only one of \`-rlt/--auto-req-limit/--polite/--balanced/--aggressive\` can be used at a time.

1. Polite (--polite)

    Set \`req-limit-per-target\` to a low value (5 rps per host:port)

2. Balanced (--balanced)

    Set \`req-limit-per-target\` to a moderate value (15 rps per host:port)

3. Aggressive (--aggressive)

    Set \`req-limit-per-target\` to a higher value (50 rps per host:port)

\`\`\`sh
afrog -T urls.txt --polite
afrog -T urls.txt --balanced
afrog -T urls.txt --aggressive
\`\`\`

## Auto Req Limit

\`--auto-req-limit\` automatically sets (and may adjust) the per-target request limit during scanning to reduce the need for manual tuning.

\`\`\`sh
afrog -T urls.txt --auto-req-limit
\`\`\`

## Smart

When conducting batch asset scanning, the scanning progress slows down as the number of assets increases, and the default scanning rate seems inadequate. However, by using the "-smart" command, you can effectively address this issue. This command dynamically adjusts the scanning rate based on the number of assets being scanned, resulting in accelerated scanning progress.

\`\`\`sh
afrog -t https://example.com -smart
afrog -T url.txt -smart
\`\`\`

## Accurate concurrency control to enhance POC validation accuracy.

In order to further enhance the accuracy of POC validation and reduce the impact caused by a large number of requests on the backlink platform, version 2.7.8 of afrog has introduced a dedicated concurrent rate control feature. This effectively disperses requests, ensuring the stability of the backlink platform and providing more accurate and reliable vulnerability scanning results.

Two new parameters have been added to regulate the concurrency of reverse link POC.

1. The default maximum requests per second for reverse link POC is set to 50. (Modification is not recommended)

Command: 
\`\`\`
afrog -t example.com -rrl 20
\`\`\`

2. The default concurrency for reverse link POC is set to 20.

Command: 

\`\`\`
afrog -t example.com -c 10
\`\`\`

Please note that the "smart" parameter in the new version will no longer affect the concurrency of reverse link POC.


# Optimzations

## Monitor Targets

Afrog has introduced the \`monitor-target\` function since version 2.3.0, which is designed to monitor inaccessible URLs. Once the specified [threshold](#max-host-errors) is reached, the URL will be added to a blacklist to prevent any further PoCs detection attempts. This feature significantly enhances afrog’s scanning speed and effectively solves the problem of prolonged progress times or false-positive hang-ups.

By default, the \`monitor-target\` function is disabled. To enable this feature, please use the command \`-monitor-target\` 或 \`-mt\`.

\`\`\`sh
afrog -t https://example.com -mt
\`\`\`

## Max Host Errors

This setting is used to limit the maximum target error threshold when the \`monitor target\` function is enabled. Note that it only takes effect after enabling this function. Default value is 3

\`\`\`sh
afrog -t https://example.com -mhe 1
\`\`\`

## Retries

The number of retries for failed HTTP requests. Defaults to 1 times

\`\`\`sh
afrog -t https://example.com -retries 3
\`\`\`

## Timeout

This attribute specifies the duration (in seconds) for waiting time before the HTTP request times out. Defaults to 10 seconds

\`\`\`sh
afrog -t https://example.com -timeout 30
\`\`\`

## Brute Max Requests

Some PoCs use \`brute\` in a rule to enumerate payload combinations (e.g., paths/users/passwords). To prevent combinational explosion, afrog provides a hard cap for the maximum requests per rule in brute mode.

- Flag: \`--brute-max-requests\`
- Default: \`5000\`
- Set to \`0\` to disable the cap

\`\`\`sh
afrog -t https://example.com --brute-max-requests 2000
\`\`\`

## Silent

During the scanning process, the \`Silent\` feature only outputs vulnerability results to the cmd console without displaying unnecessary details like the scanning progress. By default, this feature is turned off.

\`\`\`sh
afrog -t https://example.com -silent
\`\`\`

# Update

Afrog provides both version upgrade and PoC library upgrade functionalities. Starting from version \`2.3.0\`, the PoC upgrade feature is enabled by default. If you wish to disable this feature, please use the command \`disable-update-check\`.

## Update afrog engine

Update afrog engine to the latest released version. The default is no automatic update.

Here is an example update afrog command:

\`\`\`sh
afrog -un
\`\`\`

## Update PoC library

::: warning
**Deprecated since version 2.5.1.**
:::

Update afrog-pocs to latest released version. Automatic update by default.

\`\`\`sh
afrog -up
\`\`\`

## Disable Update Check

Disable automatic \`afrog-pocs\` update check. 

\`\`\`sh
afrog -t https://example.com -duc
\`\`\`

# Proxy

Afrog Proxy supports both HTTP(S) and SOCKS5 protocols and allows for the configuration of one or multiple proxy addresses. If multiple proxy addresses are needed, they can be configured by reading from a file.

## Http proxy

\`\`\`sh
afrog -t https://example.com -proxy http://127.0.0.1:1082
\`\`\`

## Socks proxy

\`\`\`sh
afrog -t https://example.com -proxy socks5://127.0.0.1:1081
\`\`\`

## Multiple proxies

\`\`\`sh
afrog -t https://example.com -proxy proxy_file.txt
\`\`\`

Here is an example \`proxy_file.txt\` file:

\`\`\`sh
http://127.0.0.1:1082
socks5://127.0.0.1:1081
\`\`\`

# Server
Start a Web Server
\`\`\`sh
afrog -web
\`\`\`

# Webhook

## Dingtalk
Start Dingtalk Webhook

\`\`\`sh
afrog -t example.com -dingtalk
\`\`\`

To enable DingTalk vulnerability push function, you need to add the following parameters to the afrog configuration file (afrog-config.yaml):
\`\`\`yaml
webhook:
  dingtalk:
    tokens:
    - "051089e**********65c6b6aa"
    - "1f7f537**********0230ce20"
    at_mobiles:
    - ""
    at_all: false
    range: high,critical
\`\`\`
**Parameter Description:**

* Tokens: This is the access_token of the DingTalk robot. Tokens are limited to the number of messages per unit time for a single robot. If necessary, multiple tokens can be initialized and randomly sent to one of the robots when sending a message.

* at_mobiles: Optional parameter, used to specify the group members to @. Leave it blank to not @ anyone.

* at_all: Optional parameter, set to true to indicate @everyone.

* range: Vulnerability notification range, the default is high and critical. Only these vulnerabilities will push messages.

Finally, the complete configuration of afrog-config.yaml is as shown in the figure

![image](https://github.com/zan8in/afrog/assets/4088460/1627eeae-04ca-4d56-a07c-a4b16879039d)


**Tutorial**

[afrog 钉钉漏洞推送，一键提前发现漏洞](https://mp.weixin.qq.com/s/87jGrcz3ZFHc3a97TX74xQ)

# OOB Out of Band
## oob
In the new version, we have introduced the \`-oob\` parameter, allowing users to specify the anti-connection platform used for scanning. Currently, the anti-connection platforms supported by afrog include ceyeio, dnslogcn, alphalog (self-built), and eyes (self-built). We will also gradually add support for more anti-connection platforms, and users are also welcome to recommend other anti-connection platforms.

\`\`\`
afrog -t example.com -oob dnslogcn  //  dnslog.cn
afrog -t example.com -oob alphalog   // alphalog
afrog -t example.com -oob xray     //  xray
afrog -t example.com                // ceyeio
\`\`\`

How to write PoCs：[How to write PoCs](https://github.com/zan8in/afrog/blob/main/afrog-helper-function.md#oob)
`;export{e as default};
