# RuleLens

RuleLens 是一个查看服务器 fail2ban 规则的桌面端面板：通过 SSH 连接多台服务器，以可视化方式查看每台服务器上 fail2ban 的规则（jail）与封禁情况。基于 [MyGo](https://mygo.egoist.dev/docs) 构建，界面使用 MyGo 的原生 UI（`ui` 包）在 GPU 上绘制（macOS Metal / Windows Direct3D 11 / Linux OpenGL），没有 WebView、没有前端构建，整个应用是一个约 10 MB 的 Go 程序。

RuleLens 只在你确认后改动服务器：解封 IP，以及新增、修改、停用或删除规则。规则的改动只写入 RuleLens 自己的文件 `/etc/fail2ban/jail.d/zz-rulelens-<规则>.local`，不改动 `jail.conf`、`jail.local` 等原有配置，删除该文件即可撤销。

## 功能

- **多服务器概览**：服务器按分组显示在侧栏，状态点标示连接与 fail2ban 状态，并显示当前封禁的 IP 数；概览页汇总所有服务器，每张卡片列出这台服务器的全部规则：监控端口、触发条件（如 `3 次 / 10 分钟`）、封禁时长与当前封禁数。
- **规则（jail）详情**：服务器页以表格列出所有 jail（可排序），选中后在右侧显示完整规则——端口与协议、触发条件、封禁时长（含递增封禁）、封禁动作（如 `nftables`、`iptables-multiport`）、日志来源（日志文件或 systemd journal 匹配）、忽略 IP、失败与封禁计数、当前封禁的 IP，以及匹配规则 failregex / ignoreregex。fail2ban 展开后的地址正则会还原为 `<HOST>`、`<ADDR>` 等标签，便于阅读。
- **封禁 IP**：所有 jail 当前封禁的 IP，含封禁时间、剩余时间与解封时间（换算为本机时钟），可筛选、排序；永久封禁单独标出。
- **封禁历史**：服务器页的「封禁历史」列出 fail2ban 封禁过的所有 IP，包括已到期或已解封的，可追溯到日志保留的最早记录（Debian / Ubuntu 默认按周轮转、保留约 5 周）。「按 IP」汇总每个 IP 被封禁的次数、涉及的规则、首次与最近封禁时间及是否仍在封禁中，便于找出反复被封的来源；「按次」列出每一次封禁的封禁时间、解封时间、时长与状态。可筛选、排序，双击 IP 查看它的每次封禁。打开此页时读取，停留在此页时随刷新与自动刷新一起更新。
- **解封 IP**：在「封禁 IP」页多选（Cmd/Ctrl、Shift 点击）后点「解封」或按 Delete，或在 jail 详情中点 IP 旁的「解封」；确认框列出将执行的命令（`fail2ban-client set <jail> unbanip <IP…>`），完成后自动重新读取。同一 IP 还被其他 jail（如 recidive）封禁时会提示，并可一键在所有 jail 中解封。
- **规则管理**：在「规则」页管理 jail。
  - **新增规则**：选择服务器上 fail2ban 预置但未启用的规则（如 `nginx-http-auth`，留空的项沿用其预置设置），或自定义一条：过滤器（`filter.d` 中的过滤器，可自动补全）、端口、日志来源（日志文件，或 systemd 日志）、触发条件（时长内失败次数）、封禁时长（可永久、可递增并设上限）与忽略 IP；「加入本机 IP」把本机在服务器上的地址加入忽略 IP，以免把自己封掉。
  - **编辑规则**：修改已有 jail 的上述设置，只写入改动的项；再次编辑时保留之前的设置。
  - **停用 / 启用**：停用写入 `enabled = false`，fail2ban 重启后仍保持停用，停用的规则留在列表末尾，可随时启用；停用会解除该规则当前的封禁。
  - **删除 / 还原配置**：删除 RuleLens 新增的规则；对服务器原有的规则，「还原配置」撤销 RuleLens 的修改。
  - 对话框实时预览将写入的文件；规则详情中的「配置」一项标出 RuleLens 新增或修改了哪些设置。
- **自动刷新**：可选不自动刷新 / 每 30 秒 / 1 分钟 / 5 分钟 / 10 分钟（默认 1 分钟，保存在 `settings.json`），定时重新读取已连接的服务器；自动刷新失败时只在页面上标出「刷新失败」，不弹提示。为避免反复用错误密码登录触发 fail2ban 封禁本机，断开或连接失败的服务器不会自动重连。
- **防火墙中的封禁**：fail2ban 在防火墙中实际创建的链、表与集合（`iptables -S` / `ip6tables -S` / `nft list table` / `ipset list` 中与 fail2ban 相关的部分）。
- **SSH 连接**：支持密码、私钥（含加密私钥口令）和 ssh-agent；读取 fail2ban 需要 root，非 root 用户通过 `sudo` 提权，sudo 密码经 SSH 会话的标准输入传给 `sudo -S`，不会出现在命令行或日志中。
- **主机指纹校验**：首次连接显示 SHA-256 指纹，确认后才信任（记录在应用自己的 known_hosts，同时读取 `~/.ssh/known_hosts`）；指纹变化时拒绝连接并给出中间人攻击警告。
- **透明可审计**：「操作日志」页记录每条执行的命令、退出码、耗时与输出。
- **状态提示**：服务器未安装 fail2ban、fail2ban 未运行、没有启用任何 jail、sudo 失败时分别给出说明。
- 密码保存在系统钥匙串（macOS Keychain / Windows 凭据管理器 / Linux Secret Service），不可用时仅保存在内存中并提示。

## 读取方式

每次刷新只执行一条 SSH 命令（以 root 运行）：用 `fail2ban-client` 所用的 Python（2 或 3 均可）加载 fail2ban 自带的客户端模块，经 fail2ban 的 socket 依次查询 `status`、每个 jail 的 `status <jail>` 与 `get <jail> …`（maxretry、findtime、bantime、ignoreip、logpath、journalmatch、failregex、actions 及各 action 的 port / protocol、`banip --with-time` 等），以 JSON 输出；随后列出防火墙中 fail2ban 的规则。读到的是正在运行的 fail2ban 实际生效的配置，而非配置文件。socket 路径从 `/etc/fail2ban/fail2ban.conf`（及 `.local`）读取。同一条命令还用 fail2ban 的配置读取模块列出配置中的全部 jail 及是否启用（用于「新增规则」中的预置规则）、`filter.d` 中的过滤器，以及 RuleLens 写入的 `zz-rulelens-*.local` 文件。

封禁历史在打开「封禁历史」页时另行读取（同样是一条以 root 运行的命令），来源依次为：

1. fail2ban 的日志文件（`logtarget`，如 `/var/log/fail2ban.log`）及 logrotate 轮转出的旧日志（`.1`、`.2.gz`、`-20261011.gz` 等，支持 gzip / bzip2 / xz 压缩），从中取出 `[jail] Ban <IP>`、`[jail] Unban <IP>` 与 `[jail] Restore Ban <IP>` 行，配对成每次封禁的起止时间。fail2ban 停止时会解除封禁、启动时再恢复，这样被打断的封禁合并为一次；
2. `logtarget` 不是文件时（如 `SYSTEMD-JOURNAL`、`SYSLOG`、`STDOUT`），读取 systemd 日志中 fail2ban 的记录；
3. 都不可用时退回 fail2ban 的数据库（`dbfile`）中的 `bans` 表。数据库只保留最近 `dbpurgeage`（默认 1 天）的封禁，且手动解封会删除对应记录，页面上会注明。

为控制数据量，每次最多读取最近 40000 条记录。仍在封禁中的 IP 以当前状态为准：日志中尚未解封、但 fail2ban 已不再封禁的记为已解封（时间未知）；正在封禁、但早于日志记录的封禁也会列出。

## 规则的写入方式

每条规则对应一个文件 `/etc/fail2ban/jail.d/zz-rulelens-<规则>.local`，内容是该 jail 的一节设置。fail2ban 最后读取 `jail.d` 中的 `.local` 文件（在 `jail.local` 之后），`zz-` 使它排在其他文件之后，因此其中的设置优先生效；没写入的设置沿用原有配置。每次改动以 root 执行一条命令：

1. 备份原文件（如有），写入新文件（或删除文件）；
2. `fail2ban-client -t` 校验全部配置；
3. `fail2ban-client reload` 重新加载：启用的 jail 启动、停用的 jail 停止，其他 jail 的封禁保留。

第 2、3 步任一失败都会还原原文件（重载失败时再重载一次），避免留下让 fail2ban 无法启动的配置；界面会显示 fail2ban 给出的原因，如「找不到规则 X 的日志文件」。时长写成 fail2ban 的格式（`10m`、`1h30m`、`1w`），永久封禁写为 `bantime = -1`。

已在 fail2ban 1.0.2（Ubuntu 24.04，nftables）与 0.11.2（Ubuntu 22.04，iptables）上验证。

## 开发

需要 Go 1.27+（`go.mod` 中的 toolchain 指令会自动下载），无需 cgo、无需 Bun。

```sh
go tool mygo dev     # 开发模式，修改代码自动重建重启
go tool mygo build   # 打包：macOS 生成 .app 与 .dmg，Linux 生成可执行文件与 .deb，Windows 生成安装程序
go tool mygo build -platform darwin/universal,windows/amd64,linux/amd64   # 交叉打包
go test ./...        # 单元测试与界面测试（无窗口运行）
```

### 发布

`.github/workflows/release.yml` 在发布版本时自动构建 macOS 安装包，Apple 芯片与 Intel 各一个，并上传到 GitHub Release：`RuleLens-<版本>-mac-arm64.dmg` 与 `RuleLens-<版本>-mac-intel.dmg`。

1. 修改 `mygo.json` 的 `version`（如 `0.5.0`），提交并推送；
2. 推送对应的标签，或在 GitHub 上发布该标签的 Release：

```sh
git tag v0.5.0 && git push origin v0.5.0
```

工作流先核对标签与 `mygo.json` 的版本一致（不一致则不构建），在 Linux 上运行测试，再在 macOS 上同时构建两个安装包（Intel 版由 Apple 芯片的机器交叉编译，并核对可执行文件的架构）。推送标签时，工作流创建 Release，两个安装包都上传后才发布；在网页上手动发布的 Release 保留原有说明，在其后附上下载说明。也可以在 Actions 页面手动运行，只构建安装包作为运行的产物，不发布。

安装包使用临时签名（ad hoc），没有 Apple 公证：其他 Mac 首次打开时需要在「系统设置 → 隐私与安全性」中允许，Release 的说明里写有步骤。

### 端到端测试

`testdata/ubuntu-fail2ban` 是一个带 sshd、sudo、rsyslog、fail2ban 与 nftables 的 Ubuntu 24.04 镜像（用户 `ops` / 密码 `rulelens`），启用了 `sshd` 与 `recidive` 两个 jail：

```sh
docker build -t rulelens-ubuntu testdata/ubuntu-fail2ban
#  国内网络可加 --build-arg APT_MIRROR=http://mirrors.aliyun.com
#  --build-arg UBUNTU=22.04 则是 fail2ban 0.11.2（iptables）
docker run -d --cap-add NET_ADMIN -p 2222:22 --name rulelens-ubuntu rulelens-ubuntu
RULELENS_E2E=127.0.0.1:2222 go test ./internal/e2e -v
```

E2E 包含三部分：经真实 SSH（sudo）读取 fail2ban 并核对 jail 配置、封禁与防火墙规则，再解封并核对，且封禁历史中有这次封禁、已解封；规则管理：新增自定义 jail 并核对生效的设置、停用、写入 fail2ban 拒绝的配置并核对已还原、修改 sshd 后还原，并确认其间其他 jail 的封禁保留；以及用 MyGo 的无窗口 Tester 驱动整个界面，完成「添加服务器 → 确认指纹 → 查看规则 → 服务器上新增封禁后由自动刷新显示 → 查看封禁 IP 与防火墙规则 → 在界面中解封并核对服务器 → 在封禁历史中查看该 IP 已解封 → 检查操作日志不含密码 → 新增规则并核对服务器 → 停用 → 删除」。测试只封禁 / 解封 `203.0.113.0/24`（TEST-NET-3）中的地址，测试用的规则结束后删除。

界面截图：`RULELENS_SNAPSHOTS=/tmp/shots go test ./internal/gui -run TestSnapshots` 会把主要页面渲染为 PNG。

## 架构

```
main.go                 组装：清单、钥匙串、主机指纹、后台任务 → 窗口
internal/
  gui/                  原生 UI（MyGo ui 包）：侧栏、概览、服务器页（规则 / 封禁 IP / 封禁历史 / 防火墙 / 日志）、对话框
  fail2ban/             读取 fail2ban（远程脚本、JSON 解析、规则模型、failregex 还原）、封禁历史、解封与规则文件的写入
  session/              连接一台服务器：SSH → 探测系统；命令审计日志
  sshx/                 SSH 客户端：认证、sudo 提权、超时取消、keepalive、known_hosts
  remote/               远程命令执行接口、Shell 转义、系统探测
  store/                服务器清单与设置（JSON，原子写入，0600）、密码保险箱
  e2e/                  针对真实 Ubuntu + fail2ban 服务器的端到端测试
```

所有 SSH 操作在后台 goroutine 中执行，结果经 `Window.Update` 回到 UI 线程。

## 已知限制

- 不支持手动封禁 IP。
- 规则管理不修改封禁动作（`action` / `banaction`）与过滤器的内容，只能选用服务器上已有的过滤器；需要 fail2ban 0.10 及以上（`fail2ban-client -t` 与不丢失封禁的 `reload`），已在 0.11.2 与 1.0.2 上验证。
- 停用或删除规则会解除该规则当前的封禁（fail2ban 停止 jail 时的行为）。
- 手动修改 `zz-rulelens-*.local` 后，RuleLens 会读取并保留其中的设置；在 jail.d 中排在其后的其他 `.local` 文件（少见）会覆盖 RuleLens 的设置。
- 封禁历史只能追溯到服务器上仍保留的日志；日志不在文件或 systemd 日志中时，只能读到 fail2ban 数据库中最近 `dbpurgeage` 内、未被手动解封的封禁。日志中记录的时间精确到秒，按服务器与本机的时钟差换算为本机时间。
- 解封使用 `unbanip` 的多 IP 形式，需要 fail2ban 0.10 及以上（已在 0.11.2 与 1.0.2 上验证）。
- jail 使用的 filter 名称无法从 fail2ban 运行时读取，界面显示的是 filter 展开后的 failregex。
- 远程命令按 POSIX `sh` 执行；fail2ban 的 socket 需要 root 访问。
