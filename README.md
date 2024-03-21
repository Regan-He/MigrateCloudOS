# MigrateCloudOS

## 测试环境

| 架构   | 引导方式 | CPU | 内存 | 磁盘 |
| ------ | -------- | --- | ---- | ---- |
| x86_64 | UEFI     | 1   | 6G   | 25G  |

## BUG

1. release,repos,rpm-config 这些包的处理有问题

```bash
dnf -y shell \
    <<EOF
    clean all
    makecache
    run
    exit
EOF

readarray -t ENABLED_REPOS < <(
    dnf repolist | awk '
$1 == "repo" && $2 == "id" && $3 == "repo" {reading=1; next}
reading && NF {print $1}
!NF {reading=0}
'
)

dnf list --showduplicates | grep -vE '[[:space:]]@'
```

```bash
dnf -y '--disablerepo=*' --noautoremove --setopt=protected_packages= --setopt=keepcache=True --repofrompath=cloudosbaseos,https://mirrors.opencloudos.tech/opencloudos/9/BaseOS/x86_64/os/ --setopt=cloudosbaseos.gpgcheck=1 --setopt=cloudosbaseos.gpgkey=file:///root/MigrateCloudOS/OpenCloud-9-gpgkey/RPM-GPG-KEY-OpenCloudOS-9 --repofrompath=cloudosappstream,https://mirrors.opencloudos.tech/opencloudos/9/AppStream/x86_64/os/ --setopt=cloudosappstream.gpgcheck=1 --setopt=cloudosappstream.gpgkey=file:///root/MigrateCloudOS/OpenCloud-9-gpgkey/RPM-GPG-KEY-OpenCloudOS-9 --repofrompath=cloudosextras,https://mirrors.opencloudos.tech/opencloudos/9/extras/x86_64/os/ --setopt=cloudosextras.gpgcheck=1 --setopt=cloudosextras.gpgkey=file:///root/MigrateCloudOS/OpenCloud-9-gpgkey/RPM-GPG-KEY-OpenCloudOS-9 --nobest list
```
