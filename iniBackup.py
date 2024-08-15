import os
import getpass
import paramiko
import tarfile
import shutil
import logging
import gzip
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import platform
from tqdm import tqdm
import tempfile
from datetime import datetime
import sys

# 设置日志记录，输出日志到指定文件
def setup_logging(log_file="./backup_restore.log"):
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

# 日志记录函数，用于记录信息到日志文件
def log(message):
    logging.info(message)

# 获取 SSH 客户端连接，返回连接对象
def get_ssh_client(host, port, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port, username, password)
        return client
    except paramiko.AuthenticationException as e:
        log(f"Failed to connect to {host}:{port}. Error: Authentication failed. {e}")
        return None
    except Exception as e:
        log(f"Failed to connect to {host}:{port}. Error: {e}")
        return None

# 衍生加密密钥，通过 PBKDF2-HMAC 生成固定长度的密钥
def derive_key(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# 使用 AES 加密数据
def aes_encrypt(data, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + encrypted_data

# 使用 AES 解密数据
def aes_decrypt(data, password):
    salt = data[:16]
    iv = data[16:32]
    encrypted_data = data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        data = unpadder.update(padded_data) + unpadder.finalize()
    except ValueError:
        raise ValueError("Decryption failed. Possibly due to an incorrect password.")
    return data

# 确保远程目录存在，如果不存在则创建
def ensure_remote_directory_exists(sftp, remote_directory):
    try:
        sftp.stat(remote_directory)
    except FileNotFoundError:
        parent_directory = os.path.dirname(remote_directory)
        if parent_directory not in ('', '/'):
            ensure_remote_directory_exists(sftp, parent_directory)
        log(f"Creating remote directory: {remote_directory}")
        sftp.mkdir(remote_directory)

# 创建备份，支持压缩和加密，并上传到目标位置
def create_backup(source, dest, compress, encrypt, password, dest_client=None):
    log("Starting backup...")
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_filename = f'backup_{timestamp}.tar.gz'
    local_backup_path = os.path.join(tempfile.gettempdir(), backup_filename)

    # 计算需要备份的文件总大小
    total_size = sum(
        os.path.getsize(os.path.join(root, file)) for root, dirs, files in os.walk(source) for file in files)

    # 创建 tar.gz 文件，支持压缩
    with tarfile.open(local_backup_path, 'w:gz' if compress else 'w') as tar:
        with tqdm(total=total_size, unit='B', unit_scale=True, desc="Creating archive") as pbar:
            for root, dirs, files in os.walk(source):
                for file in files:
                    fullpath = os.path.join(root, file)
                    tar.add(fullpath, arcname=os.path.relpath(fullpath, source))
                    pbar.update(os.path.getsize(fullpath))

    # 如果选择加密，使用 AES 进行加密
    if encrypt:
        key = password.ljust(32, '0').encode('utf-8')[:32]
        with open(local_backup_path, 'rb') as f:
            data = f.read()
        encrypted_data = aes_encrypt(data, password)
        local_backup_path += '.enc'
        with open(local_backup_path, 'wb') as f:
            f.write(encrypted_data)
        os.remove(local_backup_path[:-4])

    # 将备份文件上传到远程服务器或移动到本地目标目录
    if dest_client:
        sftp = dest_client.open_sftp()
        remote_backup_path = os.path.join(dest, os.path.basename(local_backup_path)).replace("\\", "/")
        ensure_remote_directory_exists(sftp, os.path.dirname(remote_backup_path))
        sftp.put(local_backup_path, remote_backup_path)
        sftp.close()
        log(f"Backup uploaded to {remote_backup_path}")
    else:
        shutil.move(local_backup_path, dest)

    os.remove(local_backup_path)
    log("Backup completed successfully.")

# 恢复备份，支持解密和解压缩
def restore_backup(source, dest, decrypt, password, source_client=None):
    log("Starting restore...")
    if source_client:
        sftp = source_client.open_sftp()
        try:
            log(f"Trying to access remote file: {source}")
            sftp.stat(source)
            local_backup_file = os.path.join(tempfile.gettempdir(), os.path.basename(source))
            log(f"Downloading from {source} to {local_backup_file}")

            with open(local_backup_file, 'wb') as f:
                sftp.getfo(source, f)
            log(f"Downloaded file size: {os.path.getsize(local_backup_file)} bytes")

            if os.path.getsize(local_backup_file) == 0:
                log("Downloaded file size is 0. There may have been an issue during download.")
                return
        except FileNotFoundError:
            log(f"Remote file not found: {source}")
            return
        except PermissionError:
            log(f"Permission denied for remote file: {source}")
            return
        except Exception as e:
            log(f"Error during SFTP download: {str(e)}")
            return
        finally:
            sftp.close()
    else:
        local_backup_file = source

    # 如果需要解密，使用 AES 解密文件
    if decrypt and local_backup_file.endswith('.enc'):
        try:
            with open(local_backup_file, 'rb') as f:
                data = f.read()
            decrypted_data = aes_decrypt(data, password)
            local_backup_file = local_backup_file[:-4]
            with open(local_backup_file, 'wb') as f:
                f.write(decrypted_data)
            log(f"File decrypted successfully: {local_backup_file}")
        except Exception as e:
            log(f"Error decrypting the file: {str(e)}")
            return

    # 尝试解压 tar 文件
    try:
        with tarfile.open(local_backup_file, 'r:*') as tar:
            total_size = sum(m.size for m in tar.getmembers())
            with tqdm(total=total_size, unit='B', unit_scale=True, desc="Extracting archive") as pbar:
                tar.extractall(path=dest, members=update_progress(tar, pbar))
            log(f"File successfully extracted to destination: {dest}")
    except tarfile.ReadError as e:
        log(f"Failed to extract the tar file: {str(e)}")
        return
    except Exception as e:
        log(f"Error handling the file: {str(e)}")
        return

    if os.path.exists(local_backup_file):
        os.remove(local_backup_file)

    log("Restore completed successfully.")

# 更新进度条的辅助函数
def update_progress(members, pbar):
    for member in members:
        pbar.update(member.size)
        yield member

# 验证并返回主机地址输入
def validate_host_input(prompt):
    while True:
        host = input(prompt).strip()
        if host.lower() in ["localhost", "local"]:
            return host
        elif validate_ip(host):
            return host
        elif os.path.exists(host):
            return host
        print("Invalid host address, please enter again.")

# 验证并返回 IP 地址
def validate_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        i = int(part)
        if i < 0 or i > 255:
            return False
    return True

# 验证并返回非空输入
def validate_non_empty_input(prompt):
    while True:
        data = input(prompt).strip()
        if data:
            return data
        print("Input cannot be empty, please enter again.")

# 验证并返回端口输入
def validate_port_input(prompt):
    while True:
        port = input(prompt).strip()
        if port.isdigit() and 0 < int(port) <= 65535:
            return int(port)
        elif port == '':
            return 22
        print("Invalid port number, please enter again.")

# 验证并返回路径输入，支持远程路径和自动创建
def validate_path_input(prompt, allow_creation=False, remote=False):
    while True:
        path = input(prompt).strip()
        if remote:
            if path.startswith('/') or ':' in path:
                return path
            else:
                print("Invalid remote path, please enter again.")
        else:
            if platform.system() == "Windows":
                drive, tail = os.path.splitdrive(path)
                if drive and os.path.exists(drive + '\\'):
                    if os.path.isabs(path):
                        if not os.path.exists(path) and allow_creation:
                            try:
                                os.makedirs(path)
                            except Exception as e:
                                print(f"Failed to create directory {path}. Error: {e}")
                                continue
                        return path
                    else:
                        print("Invalid path, please enter again.")
                else:
                    print("Invalid drive or path, please enter again.")
            else:
                if path.startswith('/'):
                    if not os.path.exists(path) and allow_creation:
                        try:
                            os.makedirs(path)
                        except Exception as e:
                            print(f"Failed to create directory {path}. Error: {e}")
                            continue
                    return path
                else:
                    print("Invalid path, please enter again.")

# 确认密码输入
def confirm_password(prompt):
    while True:
        password = getpass.getpass(prompt)
        confirm = getpass.getpass("Please re-enter the password to confirm: ")
        if password == confirm:
            return password
        else:
            print("Passwords do not match, please enter again.")

# 验证并返回是/否输入
def validate_yes_no_input(prompt):
    while True:
        choice = input(prompt).strip().lower()
        if choice in ['yes', 'y', 'no', 'n']:
            return choice in ['yes', 'y']
        print("Invalid input. Please enter 'yes' or 'no' or 'y' or 'n'.")

# 主程序入口，处理备份和恢复操作的选择和执行
def main():
    setup_logging()
    print("Do you want to backup or restore?")
    while True:
        action = input("Please enter your action: backup (B) or restore (R): ").strip().lower()
        if action in ['b', 'backup']:
            action = 'backup'
            break
        elif action in ['r', 'restore']:
            action = 'restore'
            break
        else:
            print("Invalid action. Please enter B for backup or R for restore.")

    if action == 'backup':
        source_host = validate_host_input(
            "Enter the source host (e.g., 192.168.1.1 or local path): ")

        if source_host.lower() in ["localhost", "local"] or os.path.exists(source_host):
            source_client = None
        else:
            source_port = validate_port_input("Enter the source port (default 22): ")
            source_user = validate_non_empty_input("Enter the source username: ")
            source_password = getpass.getpass("Enter the source password: ")
            source_client = get_ssh_client(source_host, source_port, source_user, source_password)
            if not source_client:
                return

        source_path = validate_path_input(
            "Enter the source path (e.g., /path/to/source or D:\\path\\to\\source): ")

        dest_host = validate_host_input(
            "Enter the destination host (e.g., 192.168.1.2 or local path): ")

        if dest_host.lower() in ["localhost", "local"] or os.path.exists(dest_host):
            dest_client = None
        else:
            dest_port = validate_port_input("Enter the destination port (default 22): ")
            dest_user = validate_non_empty_input("Enter the destination username: ")
            dest_password = getpass.getpass("Enter the destination password: ")
            dest_client = get_ssh_client(dest_host, dest_port, dest_user, dest_password)
            if not dest_client:
                return

        dest_path = validate_path_input(
            "Enter the destination path (e.g., /path/to/destination or D:\\path\\to\\destination): ",
            allow_creation=True, remote=(dest_client is not None))

        compress = validate_yes_no_input("Do you want to compress the backup? (yes/no): ")
        encrypt = validate_yes_no_input("Do you want to encrypt the backup? (yes/no): ")
        encryption_password = None
        if encrypt:
            encryption_password = confirm_password("Enter the encryption password: ")

        create_backup(source_path, dest_path, compress, encrypt, encryption_password, dest_client)
    elif action == 'restore':
        source_host = validate_host_input(
            "Enter the source host (e.g., 192.168.1.1 or local path): ")

        if source_host.lower() in ["localhost", "local"] or os.path.exists(source_host):
            source_client = None
        else:
            source_port = validate_port_input("Enter the source port (default 22): ")
            source_user = validate_non_empty_input("Enter the source username: ")
            source_password = getpass.getpass("Enter the source password: ")
            source_client = get_ssh_client(source_host, source_port, source_user, source_password)
            if not source_client:
                return

        source_path = validate_path_input(
            "Enter the full path of the source file (e.g., /path/to/backup/backup_20240814162234.tar.gz or D:\\path\\to\\backup\\backup_20240814162234.tar.gz): ",
            remote=(source_client is not None))

        dest_host = validate_host_input(
            "Enter the destination host (e.g., 192.168.1.2 or local path): ")

        if dest_host.lower() in ["localhost", "local"] or os.path.exists(dest_host):
            dest_client = None
        else:
            dest_port = validate_port_input("Enter the destination port (default 22): ")
            dest_user = validate_non_empty_input("Enter the destination username: ")
            dest_password = getpass.getpass("Enter the destination password: ")
            dest_client = get_ssh_client(dest_host, dest_port, dest_user, dest_password)
            if not dest_client:
                return

        dest_path = validate_path_input(
            "Enter the destination path (e.g., /path/to/destination or D:\\path\\to\\destination): ",
            allow_creation=True, remote=(dest_client is not None))

        decryption_password = None
        if source_path.endswith('.enc'):
            decryption_password = getpass.getpass("Enter the decryption password: ")

        restore_backup(source_path, dest_path, decryption_password is not None, decryption_password, source_client)

if __name__ == "__main__":
    main()
