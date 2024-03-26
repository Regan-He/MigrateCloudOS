# MigrateCloudOS

## 用法说明

> 必须使用 root 用户执行该工具。

查看用法：

```bash
sudo bash migrate-opencloudos.sh -h
```

输出如下：

```log
2024-03-23 18:27:01.274 | [INFO] | MigrateCloudOS 8to9 - Begin logging at Sat Mar 23 18:27:01 2024.
Usage: migrate-opencloudos.sh [OPTIONS]

Options:
        -h      Display this help
        -m      Check for matching RPM packages on the new DNF repo
        -u      Upgrade to OpenCloudOS 9
        -U      Pre-upgrade the system to the latest status
        -V      Verify rpms in the system
```

参数说明：

| 选项 | 说明                                                |
| ---- | --------------------------------------------------- |
| -h   | 显示此帮助                                          |
| -m   | 检查新 DNF 仓库中与旧 RPM 包匹配的 RPM 包           |
| -u   | 升级到 OpenCloudOS 9                                |
| -U   | 预升级系统到最新状态，然后再升级到 OpenCloudOS 9    |
| -V   | 验证系统安装的 RPM 包，生成报告(耗时较长，非必选项) |

## 使用方法

1. 将该工具复制到一个非临时目录中，建议直接放置在 root 用户的家目录，如 /root/MigrateCloudOS。
2. 执行升级命令：

   ```bash
   # 匹配RPM包生成报告，预升级，升级，检查RPM包生成报告
   bash migrate-opencloudos.sh -mUuV
   ```

   > 全参数升级耗时较长，为了快速升级，可以仅运行 `bash migrate-opencloudos.sh -u`

3. 等待系统升级完成，直到看到 `Done, please reboot your system.`。

## 文档

设计原理及测试报告请查看[docs](./docs/ "./docs")。

```log
.
├── README.md
├── docs
│   ├── images
│   │   ├── 01-oc8-setting-about.png
│   │   ├── 02-oc8-pkg-count.png
│   │   ├── 03-oc8-legacy-grub.png
│   │   ├── 03-oc8-uefi-grub.png
│   │   ├── 04-oc8-finish-upgrade1.png
│   │   ├── 04-oc8-finish-upgrade2.png
│   │   ├── 05-oc9-legacy-grub.png
│   │   ├── 05-oc9-uefi-grub.png
│   │   ├── 06-oc9-first-login.png
│   │   ├── 07-oc9-setting-about.png
│   │   └── 08-oc9-pkg-count.png
│   ├── 测试报告.md
│   └── 软件设计说明书.md
├── migrate-opencloudos.sh
├── resources
│   └── RPM-GPG-KEY-OpenCloudOS-9
├── tests
│   └── copy-to-testenv.sh
├── upgrade-info
└── upgrade-logs
```
