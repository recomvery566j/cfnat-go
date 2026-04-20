# CF_NAT (支持 UDP 版本)

本项目的源代码衍生自股神频道的 go 源码 (https://t.me/CF_NAT/39004)。功能实现与原版 cfnat 保持一致，核心改进在于增加了对 UDP 的支持。

## 核心功能与性能

当前的 cfnat 可以同时代理 1234（默认端口）的 TCP (h2) 和 UDP (h3) 流量。

**实测性能表现：**
* 测速环境：美西节点 + Cloudflare 香港节点
* 延迟对比：H3 协议 (182ms) 优于 H2 协议 (200ms)
* 速率说明：由于部分服务商对 UDP 存在限速机制，H3 的峰值速度存在低于 H2 的情况。但 H3 能够提供更低的通信延迟，自行测试。

## 编译与下载

目前仅通过 GitHub Actions 编译并测试了以下版本：
* 64位 Linux 版本
* 64位 Windows 版本

**获取方式：**
1. 直接前往本仓库的 Actions 页面下载最新的编译产物。
2. Fork 本仓库后，手动编译执行 Actions 。

## 客户端替换说明 (Windows)

如果你使用 Windows 系统，下载的电脑版本可以直接替换图形化客户端项目中的同名文件。
* 兼容目标：[CFnat-Windows-GUI](https://github.com/cmliu/CFnat-Windows-GUI)
* 系统支持：Windows 10 已测试可直接替换运行，Windows 7 未作专门编译与测试。
