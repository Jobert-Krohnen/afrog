const e=`The first time you start afrog, it will automatically create a configuration file called \`afrog-config.yaml\`, which will be saved in the current user directory under \`$HOME/.config/afrog/afrog-config.yaml\`.

## Configuration file

The first time you start afrog, it will automatically create a configuration file called \`afrog-config.yaml\`, which will be saved in the current user directory under \`$HOME/.config/afrog/afrog-config.yaml\`.

Here is an example config file:

\`\`\`yaml
reverse:
  ceye:
    api-key: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    domain: "xxxxxx.cey2e.io"
  dnslogcn:
    domain: dnslog.cn
  jndi: (Deprecated)
    jndi_address: ""
    ldap_port: ""
    api_port: ""
  eye: (Deprecated)
    host: ""
    token: ""
    domain: ""
  alphalog:
    domain: dnslogxx.sh
    api_url: "http://dnslogxx.sh/"
  xray:
    x_token: "xraytest"
    domain: dnslogxx.sh
    api_url: "http://x.x.0.x:8777"
\`\`\`

\`reverse\` is a reverse connection platform used to verify command execution vulnerabilities that cannot be echoed back. Currently, only ceye can be used for verification. 

### Ceye Configuration
To obtain ceye, follow these steps:

- Go to the [ceye.io](http://ceye.io/) website and register an account.
- Log in and go to the personal settings page.
- Copy the \`domain\` and \`api-key\` and correctly configure them in the \`afrog-config.yaml\` file.
### Dnslogcn
No configuration required, but unstable
[dnslog.cn](http://dnslog.cn/)

### Alphalog
Need to build services
[alphalog](https://github.com/AlphabugX/Alphalog)

### Xray
Need to build services
[xray](https://docs.xray.cool/tools/xray/advanced/reverse)

### JNDI Configuration (Deprecated)

The JNDI vulnerability refers to security vulnerabilities that exploit the JNDI (Java Naming and Directory Interface) functionality in Java applications. This type of vulnerability can lead to remote code execution or other security issues.

To obtain JNDI, follow these steps:

- To obtain the source code and compile the JAR file, please visit the official website [github.com/r00tSe7en/JNDIMonitor](https://github.com/r00tSe7en/JNDIMonitor). Alternatively, you can go to the official afrog website [afrog/helper/jndi](https://github.com/zan8in/afrog/tree/main/helper/jndi) to download the pre-compiled JAR file
- Upload the \`JNDIMonitor-2.0.1-SNAPSHOT.jar\` file to the server (such as a VPS server), and execute the following startup command:

\`\`\`sh
java -jar ./JNDIMonitor-2.0.1-SNAPSHOT.jar -i 0.0.0.0 -l 1389 -p 3456
\`\`\`

Below are example methods for writing POCs. [Please click to view](https://github.com/zan8in/afrog/wiki/Examples#solr-log4j-rce).

`;export{e as default};
