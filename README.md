# MSST-Net Core 3.1

MSST-Net 是面向朋友联机、Minecraft 等游戏和小型可信网络的私有虚拟局域网。
本仓库是它的 **Core**：以系统服务运行的特权网络守护进程，负责节点与路径管理、
WireGuard 加密数据面、NAT 穿透与中转、ACL、DNS 和游戏发现。

图形界面与 WebUI 在 [控制器仓库](https://github.com/MSST-Net-Developers/msst-net-controller-31x)，
二者通过本地 IPC 通信；安装、升级与回滚由
[安装器](https://github.com/MSST-Net-Developers/msst-net-installer-31x) 负责。

## 文档

使用教程、部署说明与常见问题见文档站：**<https://msst-net.msst2031.cn>**

本仓库 `docs/` 下是面向开发者的协议与设计文档（IPC 协议、中转与 Coordinator 的对接要求等）。

## 安装

推荐使用安装器，它会同时安装 Core 与所选控制器并注册系统服务。各平台的预编译文件与
Docker 镜像（`abjust/msstnet31x-core`）见本仓库的 Releases。

## 从源码构建

```sh
cargo build --release --bin msst-net-core
cargo test --workspace
```

需要较新的 stable Rust（edition 2024）。

## 许可证

[MIT](LICENSE)。第三方依赖的许可证见 [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt)。
