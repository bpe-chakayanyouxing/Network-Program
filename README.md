# MCChat：基于多播的去中心化聊天与文件传输

"带有文件传输功能的多播聊天工具"课程作业的实现。**没有服务器、没有中转、没有中心消息存储**：每个参与者运行同一个程序，文本和文件分块直接发送到 IPv4 多播组 `239.255.42.99:50000`。

## 目录结构

```
MCChat代码整理/
├── Windows/                          Windows 平台：代码 + 启动器 + 提示
│   ├── mcchat.py                     主程序
│   ├── run.bat                       双击启动（自动装依赖、提示节点名和网卡 IP）
│   ├── test_driver.py                自动化测试（33 项断言）
│   └── 运行提示.txt                   Windows 运行提示（启动步骤/命令表/防火墙/文件位置）
├── Ubuntu/                           Ubuntu 平台：代码 + 提示
│   ├── mcchat.py                     主程序（与 Windows/ 里的完全相同）
│   ├── test_driver.py                自动化测试（33 项断言）
│   └── 运行提示.txt                   Ubuntu 运行提示（依赖安装/启动/IGMP 验证/自动播放）
├── 测试媒体/                          手动 /file 演示用的媒体文件
│   ├── sample.mp4                    6 秒 H.264 视频（648,721 B / 634 块）
│   └── test.wav                      4 秒 440 Hz 音频（705,644 B / 690 块）
├── MCChat演示录屏(Ubuntu版）.mp4       41 秒，Ubuntu 三窗口演示录屏（3.7 MB）
├── MCChat双机实验视频.mov              两台 Windows 直连实测的过程录像（约 1.1 GB）
└── README.md                          本文件
```

两个平台文件夹里的 `mcchat.py` 是**同一份代码的两份拷贝**（跨平台、零修改），改动时请两边同步。运行产生的 `downloads\`、`logs\`、`state\` 等目录会自动建在各自平台文件夹里，互不干扰。

## 两段演示视频

| 视频 | 内容 | 来源 |
|---|---|---|
| `MCChat演示录屏(Ubuntu版）.mp4`（41 s） | Ubuntu 虚拟机里 Alice/Bob/Carol 三个终端窗口：互相发现 → 多播文本 → `/file sample.mp4` 三端收文件 → `/kick Carol` 后 Carol 只见 `[LOCKED]` 密文 → `/leave` 后仍能发送 | 在 VM 里用 `demo.sh` 驱动整个流程、ffmpeg 录桌面生成 |
| `MCChat双机实验视频.mov`（约 1.1 GB） | 两台 Windows 主机网线直连的完整实测过程，对应实验报告 7.5 节：阶段一 Alice/Bob（文本、视频 634/634、`/leave` 后发送、`/kick` epoch 14）；阶段二 citrine/Jason/abc 三节点（1→N、踢出 abc 后 Jason 正常、abc 只见 `[LOCKED]`） | 实验时人工录制 |

两段视频与报告中的 27 张截图互相印证：录屏看过程，截图看报文细节（`[SEND]`/`[RECV]` 计时、`[KICK]`、`[LOCKED]`、`[KEY]` epoch）。

## 两平台运行史（同一份代码，零修改）

| 阶段 | 环境 | 运行方式 | 结果 |
|---|---|---|---|
| 开发/测试 | Ubuntu 22.04 VM，Python 3.10，`cryptography` 3.4.8 | `python3 mcchat.py --name Alice` × 3 | 33 项自动化测试全 PASS；tcpdump/IGMP/pcap 取证 |
| 双机实测 | Windows 10/11，Python 3.12，`cryptography` 49.x | 两台电脑网线直连，双击 `run.bat` | 文本/文件（634/634，发送 1.012 s、接收 0.983 s、e2e 1.282 s）、`/leave` 后发送、`/kick`（epoch 14）、citrine/Jason/abc 三节点 1→N 与踢人 |

主程序从 Ubuntu 拷到 Windows **未改一行**。平台差异只有两点：

1. **启动器**：Ubuntu 直接命令行；Windows 用 `run.bat`（检查 Python、自动装 `cryptography`、提示节点名和 `--iface`）。
2. **播放**：`--open` 调用 `xdg-open`（Linux 收完自动弹播放器）；Windows 上收到文件保存在 `downloads\<节点名>\`，需手动双击播放。

另外，直连链路（无路由器）下必须显式 `--iface 直连网卡IP`——自动探测走默认路由，多网卡（VMware/Wi-Fi）时可能选错出口。

## 快速开始

要求：Python 3.8+，`pip install cryptography`。

- **Windows**：进 `Windows/` 双击 `run.bat`，按提示输入节点名和直连网卡 IPv4。
- **Ubuntu/Linux**：进 `Ubuntu/`，三个终端分别 `python3 mcchat.py --name Alice / Bob / Carol`。

详细步骤、命令表（`/members`、`/file`、`/kick`、`/leave`、`/join`、`/keyinfo`）、IGMP 验证方法见两个平台文件夹里的 `运行提示.txt`。

## 功能

- **多播文本 1-N**：一条消息，所有加入多播组的成员同时收到。
- **多播文件传输**：1024 字节/块，接收端按偏移落盘；文件块 1109 B < UDP 1472 B，不触发 IP 分片。
- **成员发现**：每 2 秒多播签名 HELLO（名字、IP、主机名、MAC、公钥、epoch），`/members` 显示当前成员。
- **退出/加入**：`/leave` 执行 `IP_DROP_MEMBERSHIP` 停止接收（发送 socket 不受影响，仍能发）；`/join` 重新加入并领取新密钥。
- **踢人 = 密钥轮换**：epoch+1、新 AES 组密钥只发给被踢者以外的人；被踢者仍能收到 UDP 包，但没有新密钥，只能看到 `[LOCKED]` 密文。
- **非对称密钥**：RSA-2048 身份（ID=公钥指纹）+ RSA-OAEP 逐人分发组密钥 + RSA-PSS 签名控制报文；KEY_GRANT 明文 84 B，加签后实测 601 B。
- **密钥时效性**：组密钥带 epoch、`valid_from`/`valid_to`，默认 60 秒轮换、120 秒有效期，过期/旧 epoch 拒收。
- **不做差错管理**：按课程要求，无 ACK、无重传、无 FEC；只有 1 ms/块的发送节流。

## 自动化测试

```bash
python test_driver.py    # 在 Windows/ 或 Ubuntu/ 目录里跑都可以
```

同机启动 3 实例（`SO_REUSEADDR` 共用组端口，各自唯一 `ctrl_port`），覆盖：加入/发现/成员表、文本 1-N、文件三接收 + SHA-256 逐字节校验、踢人 LOCKED、`/leave` 后仍能发、`/join` 恢复接收、密钥周期轮换。测试音频由脚本自动生成，不需要 `测试媒体/` 里的文件。

实测计时：Ubuntu VM 上 33 项全 PASS，`test.wav` 发送 0.909 s / 接收 0.908–0.909 s、`sample.mp4` 0.869 s；双机直连 `sample.mp4` 发送 1.012 s / 接收 0.983 s / e2e 1.282 s（≈0.64 MB/s）。

## 协议要点

69 字节二进制头（`!4sBIQ16s16sI12sI`，网络字节序）：magic `MCH1`、type、epoch、seq、sender_id、file_id、chunk_index、nonce、payload_len。类型：HELLO/BYE/CHAT/FILE_START/FILE_CHUNK/FILE_END/JOIN_REQ/EPOCH_NOTICE/KICK_NOTICE/KEY_REQ/KEY_GRANT。AAD 绑定头字段防篡改。协调者 = 在线成员中 `min(member_id)`，确定性选举，不是服务器。

## 限制

- 无 ACK/重传/FEC；丢块留空洞（按课程要求）。
- 开放组：被踢者可换新身份重新加入（Sybil）；任意成员可发起踢人。
- 无完美前向保密；数据包不逐个签名；无重放窗口。
- Wi-Fi AP 的 IGMP snooping 可能剪枝多播；跨网需调大 TTL 或 mbone/隧道。

完整实验报告（27 张截图、14 张表、两平台实测数据）见提交包 `REPORT.pdf` / `REPORT.docx`；报告附录 B 列出了全部证据文件（截图、录屏、pcap、日志）。

> 提示：`MCChat双机实验视频.mov` 约 1.1 GB；如需上传或随压缩包提交，可先用格式工厂 / HandBrake 转成 MP4（通常能压到几十 MB），画面内容不受影响。
