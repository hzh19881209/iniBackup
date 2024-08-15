# iniBackup
`iniBackup` 是一个用于本地和远程备份与恢复的 Python 脚本，支持数据压缩和加密。

## 目录
- [特性]
- [安装要求]
- [安装步骤]
- [使用方法]
- [注意事项]
- [许可证]

## 特性
- 本地到本地、本地到远程、远程到本地的备份与恢复。
- 支持压缩备份文件。
- 支持备份文件的 AES 加密。
- 支持多平台（Windows 和 Linux）。

## 安装要求
- Python 3.8 或更高版本。
- pip（Python 的包管理工具）。

## 安装步骤
1. 安装 Python
请确保系统上安装了 Python 3.8 或更高版本。你可以通过以下命令检查 Python 版本：
python --version
如果没有安装 Python，可以从 Python 官方网站 下载并安装适用于你的操作系统的最新版本。
推荐版本
Python 3.12.4 该版本有经过验证可以正常运行脚本。

3. 安装 pip
通常，Python 会自带 pip 如果没有安装 pip，可以按照以下步骤安装：
python -m ensurepip --upgrade

3. 克隆或下载此项目
你可以使用 Git 克隆此仓库，或者直接从 GitHub 上下载项目的 ZIP 文件并解压：
git clone https://github.com/hzh19881209/iniBackup.git
cd iniBackup

5. 安装依赖库
使用以下命令安装脚本所需的依赖库：
pip install -r requirements.txt 可将下方的依赖库文本复制粘贴到requirements.txt
如果你没有 requirements.txt 文件，可以手动安装所需的库：
paramiko==3.4.0
cryptography==42.0.7
tqdm==4.66.2
pytz==2024.1
setuptools==69.1.0
scp==0.15.0

pip install paramiko cryptography tqdm pytz setuptools scp

使用方法
1. 运行脚本
你可以通过以下命令运行备份脚本：
python iniBackup.py

2. 备份操作
运行脚本后，你会被提示选择备份或恢复操作。选择 "B"（备份）进行备份操作。
选择备份源：输入源主机地址或本地路径。
选择目标位置：输入目标主机地址或本地路径。
压缩与加密：你可以选择是否压缩和加密备份文件。

3. 恢复操作
选择 "R"（恢复）进行恢复操作。
选择源文件：输入完整的备份文件路径。
选择恢复位置：输入目标恢复路径。
解密（如有必要）：如果备份文件已加密，请输入解密密码。

注意事项
SSH 配置：如果你打算使用远程备份/恢复功能，确保目标服务器已配置 SSH。
磁盘空间：请确保目标存储位置有足够的磁盘空间来存储备份文件。
权限：确保运行脚本的用户具有访问源文件和写入目标位置的权限。

许可证
本项目使用 MIT 许可证 开源。详情请参阅许可证文件。
