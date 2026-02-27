const e=`### I can not run it

Hi,
i setup it using git clone then iam trying to run it but i do not know why or what should i do next.
Any help about the next steps to run it ?

[-> Best answer <-](https://github.com/zan8in/afrog/wiki/Getting-Started#installation)

### Which API Key and which Domain should we have to configure in afrog-config.yaml?

[-> Best answer <-](https://github.com/zan8in/afrog/wiki/configuration#reverse)

### How to configure proxy?

[-> Best answer <-](https://github.com/zan8in/afrog/wiki/Usage#proxy)

### Is the poc format of afrog and nuclei interchangeable?

No

The \`info\` section of afrog's PoC format is borrowed from nuclei, while the rest is more heavily influenced by xray.

### Is the poc format of afrog and xray interchangeable?

No

The PoC formats of afrog and xray are similar, especially in the \`rules\` section, which is almost interchangeable. However, the \`info\` section in afrog and the \`details\` section in xray are different and would benefit more from borrowing the format of nuclei.

### Afrog Update failed?

If the command 'afrog.exe -update' is executed, the following error may occur:

_**Error Info**_

[FTL] could not install latest release: looking up path of "afrog.exe": exec: "afrog.exe": cannot run executable found relative to current directory

**How to solve the above problems?**

Need to add afrog.exe to the environment variable.

To add afrog.exe to the environment variable in **Windows**, you can follow these steps:

\`\`\`
1. Right-click on "This PC" and select "Properties".
2. In the left pane, select "Advanced system settings".
3. Click on the "Environment Variables" button.
4. Under "System Variables", find "Path" and double-click to edit.
5. Click the "New" button and enter the path where the afrog.exe file is located.
6. Click the "OK" button to save the changes.
7. Close all open windows, reopen the command prompt, and type the "afrog" command to test if the addition was successful.
\`\`\`

To add afrog to the environment variable in **Linux/macOS**, you can follow these steps:

\`\`\`
1. Open the Terminal application.
2. Enter the command: sudo nano /etc/paths.
3. Add the following line to the end of the file: /path/to/afrog, where /path/to/afrog is the path to the afrog file.
4. Save the file and exit the editor.
5. Enter the command: source /etc/paths to update the configuration.
6. Enter the command afrog to test if the addition was successful.
7. Note that if you are using a different shell, such as bash or zsh, you may need to edit the corresponding configuration file (e.g., ~/.bashrc  or ~/.zshrc) and add the appropriate path.
\`\`\`

### --req-limit-per-target 参数的优点
\`--req-limit-per-target\` 的核心价值是把“限速”从**全局维度**细化到**单目标（host:port）维度**。它解决的是 \`-rate-limit\` 解决不了的那类问题：同一时间把请求集中打到某一个目标/某一个反连平台/某一个代理出口时，引发封禁、拥塞、误判或影响正常上网。

**优点（相对 -rate-limit 的补充能力）**
- **控制对单个目标的压力**：\`-rate-limit\` 只限制全局 QPS，但并不能阻止“25 个并发恰好都在打同一个 host”的情况；\`--req-limit-per-target\` 能保证这个 host 每秒最多 N 个请求。
- **降低被 WAF/限流/封禁概率**：很多防护是按“同 IP → 单站点”维度做限流/熔断的，而不是按你工具的全局 QPS。per-target 限速可以显著降低触发概率。
- **更稳定、更不影响日常网络**：当扫描集中到某些站点时，per-target 限速能减少对代理/带宽/浏览器访问同站点的抢占，缓解“扫描时上网巨慢”的情况。
- **对反连/OOB 相关 PoC 更友好**：反连平台经常是“单域名/单端口”集中请求，per-target 限速可以避免把平台打爆导致漏报/延迟。

**为什么有了 -rate-limit 还需要 --req-limit-per-target**
- \`-rate-limit\` 解决的是“全局总吞吐不要太高”，避免把**你的机器/你的网络/你的代理出口**打满。
- \`--req-limit-per-target\` 解决的是“不要对某一个目标打得太猛”，避免把**目标站/某个 host/某个端口/某个 OOB 平台**打挂或触发防护。
- 两者不是替代关系：一个是“总量阀门”，一个是“单点阀门”。在多目标扫描里，常见情况是：
  - 全局 QPS 看似合理（比如 150/s）
  - 但某一两个 host 因为响应快/命中规则多/并发集中，瞬间承受过高 rps → 触发限流/封禁/网络拥塞  
  这就是 per-target 限速存在的意义。

**最佳应用场景（什么时候最值得开）**
- **少目标高并发**：例如只扫 1～20 个目标，但 \`-c\` 很高；这时请求很容易集中到单个 host，per-target 限速非常关键。
- **目标容易限流/封禁**：有明显 WAF、CDN 限速、登录口、管理后台、API 网关等，对“突刺流量”敏感的站点。
- **使用代理/网关/扫描时影响上网**：afrog 扫描时候 “浏览器打开网页巨慢甚至打不开”，很多时候是某些目标或某些端口把代理连接池/带宽抢占了；per-target 限速能明显缓解。
- **反连/OOB PoC 或集中域名**：反连平台、回连检测点、单域名集中请求的场景，开 per-target 限速能避免平台拥塞导致误差。
- **需要更高稳定性而不是最高速度**：追求“更少漏报/更少误判/更少卡顿”的批量扫描。

建议：
- **扫很多分散目标**：优先用 \`-rate-limit\`（简单、效果直观）
- **扫少量目标/单点压力大/影响上网**：优先用 \`--req-limit-per-target\` 或 \`--balanced/--polite\`（更对症）
- **不想调参**：用 \`--auto-req-limit\`（自动兜底）

### brute 会发多少请求？如何避免组合爆炸？

\`brute\` 是规则级枚举能力，支持对一个或多个变量做枚举：
- \`mode: clusterbomb\` 会做笛卡尔积组合，请求量 = 各列表长度相乘
- \`mode: pitchfork\` 会按索引对齐组合，请求量 = min(各列表长度)

为避免组合爆炸带来的扫描变慢/目标限流/误封，建议开启运行时硬阈值：

\`\`\`sh
afrog -t https://example.com --brute-max-requests 2000
\`\`\`

默认 \`--brute-max-requests\` 为 5000，设置为 0 表示不限制。

### brute 的 commit / continue 怎么选？

- \`continue: false\`：一旦命中就停止枚举（更快、更省请求）
- \`continue: true\`：命中后继续枚举（用于需要统计/比对，或希望拿到最后一次命中）

\`commit\` 用于决定命中后保留哪一次尝试的变量与 request/response：
- \`winner\`/\`first\`：保留首次命中（默认）
- \`last\`：保留最后一次命中（常与 \`continue: true\` 配合）
- \`none\`：不保留 brute payload 变量，但保留命中的 request/response（减少对后续规则的变量污染）
`;export{e as default};
