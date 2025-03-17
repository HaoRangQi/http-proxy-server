"""
HTTPS中间人代理服务器
====================

这是一个功能完整的HTTPS中间人代理服务器，可以拦截、记录和修改HTTP/HTTPS流量。
主要功能包括：
1. 支持HTTP和HTTPS请求的拦截和记录
2. 动态生成域名证书，实现HTTPS中间人攻击
3. 提取特定URL的请求头信息（如Authorization令牌）
4. 支持通过上游代理（如Clash）转发请求
5. 实时配置更新，无需重启服务器

作者: AI助手
版本: 1.0
日期: 2025-03-14
"""

import socket
import ssl
import threading
import os
import datetime
import logging
import urllib.parse
import yaml
import json
import re
from OpenSSL import crypto
from pathlib import Path
import time
import copy
import requests

# 默认配置
# 如果配置文件不存在，将使用这些默认值
DEFAULT_CONFIG = {
    "proxy": {
        "host": "127.0.0.1",  # 代理服务器监听地址
        "port": 6000          # 代理服务器监听端口
    },
    "logging": {
        "level": "INFO",      # 日志级别: DEBUG, INFO, WARNING, ERROR, CRITICAL
        "file": "proxy.log"   # 日志文件路径
    },
    "certificates": {
        "dir": "certs",                # 证书存储目录
        "name_prefix": "proxy_"        # 证书文件名前缀
    },
    "recording": {
        "enabled": False,     # 是否记录所有请求和响应
        "dir": "logs"         # 记录文件存储目录
    },
    "header_extraction": [
        {
            "name": "API认证提取",
            "url_pattern": "https://api.example.com/completion",  # 要监控的URL
            "extract_header": "Authorization",                    # 要提取的请求头
            "output_file": "auth/api_tokens.txt",                 # 提取内容保存路径
            "refresh_interval": 30,                               # 刷新间隔（分钟）
            "verbose_logging": False,                             # 是否打印详细日志
            "local_storage": {                                    # 本地文件存储配置
                "enabled": True                                   # 是否保存到本地文件
            },
            "remote_push": {                                      # 远程接口推送配置
                "enabled": False,                                 # 是否启用远程推送功能（全局开关）
                "endpoints": [                                    # 远程接口端点列表
                    {
                        "name": "主要接口",                        # 接口名称
                        "enabled": True,                          # 是否启用此接口
                        "url": "http://your-server:3000/admin/update-tokens",  # 接口URL
                        "method": "POST",                         # 请求方法
                        "headers": {                              # 请求头
                            "Content-Type": "application/json",
                            "X-Admin-Key": "your-admin-key"
                        },
                        "data_format": '{"tokens": ["$TOKEN"]}'   # 数据格式，$TOKEN将被替换为实际令牌值
                    }
                ]
            }
        }
    ],
    "upstream_proxy": {
        "enabled": True,              # 是否使用上游代理
        "host": "127.0.0.1",          # 上游代理地址
        "port": 7890                  # 上游代理端口
    },
    "realtime_config": {
        "enabled": True,              # 是否启用实时配置
        "check_interval": 10          # 检查配置变更的间隔（秒）
    }
}

# 加载配置文件
def load_config(config_file="config.yaml"):
    """
    加载配置文件，如果文件不存在则创建默认配置文件
    
    参数:
        config_file: 配置文件路径
        
    返回:
        配置字典
    """
    config = DEFAULT_CONFIG
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                # 递归更新配置
                def update_config(default, user):
                    for key, value in user.items():
                        if isinstance(value, dict) and key in default:
                            update_config(default[key], value)
                        else:
                            default[key] = value
                update_config(config, user_config)
            logger.info(f"已加载配置文件: {config_file}")
        else:
            # 创建默认配置文件
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            logger.info(f"已创建默认配置文件: {config_file}")
    except Exception as e:
        logger.error(f"加载配置文件时出错: {e}")
    return config

# 初始化日志
def setup_logging(config):
    """
    设置日志系统
    
    参数:
        config: 配置字典
        
    返回:
        logger对象
    """
    log_level = getattr(logging, config["logging"]["level"].upper())
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(config["logging"]["file"]),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

# 全局变量
logger = logging.getLogger(__name__)  # 临时logger，将在加载配置后重新设置
CONFIG = None

def create_ca_cert(config):
    """
    创建CA证书和私钥，如果已存在则跳过
    
    参数:
        config: 配置字典
        
    返回:
        (ca_cert_file, ca_key_file): CA证书和私钥文件路径
    """
    cert_dir = Path(config["certificates"]["dir"])
    cert_dir.mkdir(exist_ok=True)
    
    # 使用前缀
    prefix = config["certificates"].get("name_prefix", "")
    ca_cert_file = cert_dir / f"{prefix}ca.crt"
    ca_key_file = cert_dir / f"{prefix}ca.key"
    
    if ca_cert_file.exists() and ca_key_file.exists():
        logger.info("CA证书已存在，跳过创建")
        return ca_cert_file, ca_key_file
    
    # 创建密钥对
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    # 创建自签名证书
    cert = crypto.X509()
    cert.get_subject().C = "CN"
    cert.get_subject().ST = "Beijing"
    cert.get_subject().L = "Beijing"
    cert.get_subject().O = "HTTP Proxy"
    cert.get_subject().OU = "HTTP Proxy CA"
    cert.get_subject().CN = "HTTP Proxy CA"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10年有效期
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    
    # 保存证书和私钥
    with open(ca_cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(ca_key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    logger.info(f"CA证书已创建: {ca_cert_file}")
    logger.info("请将CA证书安装到系统/浏览器信任列表中")
    return ca_cert_file, ca_key_file

def create_domain_cert(domain, config):
    """
    为特定域名创建证书，使用CA证书签名
    
    参数:
        domain: 域名
        config: 配置字典
        
    返回:
        (cert_file, key_file): 域名证书和私钥文件路径
    """
    cert_dir = Path(config["certificates"]["dir"])
    # 使用前缀使证书名称更具辨识度
    prefix = config["certificates"].get("name_prefix", "")
    cert_file = cert_dir / f"{prefix}{domain}.crt"
    key_file = cert_dir / f"{prefix}{domain}.key"
    ca_cert_file, ca_key_file = create_ca_cert(config)
    
    if cert_file.exists() and key_file.exists():
        return str(cert_file), str(key_file)
    
    # 加载CA证书和私钥
    with open(ca_cert_file, 'rb') as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(ca_key_file, 'rb') as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    
    # 创建域名证书
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    cert = crypto.X509()
    cert.get_subject().C = "CN"
    cert.get_subject().ST = "Beijing"
    cert.get_subject().L = "Beijing"
    cert.get_subject().O = "Proxy"
    cert.get_subject().OU = "Proxy Unit"
    cert.get_subject().CN = domain
    cert.set_serial_number(int(datetime.datetime.now().timestamp()))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # 1年有效期
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(k)
    
    # 添加SAN扩展
    san_extension = [f"DNS:{domain}"]
    cert.add_extensions([
        crypto.X509Extension(
            b"subjectAltName", 
            False, 
            ", ".join(san_extension).encode()
        )
    ])
    
    cert.sign(ca_key, 'sha256')
    
    # 保存证书和私钥
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    logger.info(f"为域名 {domain} 创建了证书")
    return str(cert_file), str(key_file)

def log_data(direction, host, data, config):
    """
    记录请求/响应数据，并处理特殊URL
    
    参数:
        direction: 数据方向，"请求"或"响应"
        host: 主机名
        data: 原始数据
        config: 配置字典
    """
    try:
        decoded_data = data.decode('utf-8', errors='replace')
        
        # 无论recording是否启用，都检查特殊URL
        process_special_urls(host, direction, decoded_data, data, config)
        
        if not config["recording"]["enabled"]:
            # 只记录简短日志到控制台
            try:
                first_line = decoded_data.split('\n')[0]
                logger.debug(f"{direction} {host}: {first_line}")
            except:
                pass
            return
        
        log_dir = config["recording"]["dir"]
        log_file = f"{log_dir}/{host}.log"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        with open(log_file, 'a', encoding='utf-8') as f:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"\n{'='*50}\n")
            f.write(f"{timestamp} - {direction}\n")
            f.write(f"{'='*50}\n")
            f.write(decoded_data)
            f.write("\n")
        
        # 打印简短日志到控制台
        first_line = decoded_data.split('\n')[0] if '\n' in decoded_data else decoded_data[:100]
        logger.info(f"{direction} {host}: {first_line}")
        
    except Exception as e:
        logger.error(f"记录数据时出错: {e}")

def process_special_urls(host, direction, decoded_data, raw_data, config):
    """
    处理特殊URL的请求，提取指定的请求头
    
    参数:
        host: 主机名
        direction: 数据方向，"请求"或"响应"
        decoded_data: 解码后的数据
        raw_data: 原始数据
        config: 配置字典
    """
    try:
        for rule in config["header_extraction"]:
            special_config = rule
            url_pattern = special_config["url_pattern"]
            url_host = url_pattern.split("//")[1].split("/")[0]  # 提取主机部分
            verbose_logging = special_config.get("verbose_logging", False)  # 获取日志详细程度设置
            
            # 更宽松的检测 - 只要主机名匹配且是请求方向
            if direction == "请求" and (url_host in host or host in url_host):
                # 根据verbose_logging设置决定是否打印详细日志
                if verbose_logging:
                    logger.info("\n" + "!"*80)
                    logger.info(f"!!! 检测到可能的特殊URL主机: {host} (模式: {url_pattern}) !!!")
                    logger.info("!"*80 + "\n")
                    logger.info(f"完整请求内容:\n{decoded_data[:2000]}...")
                else:
                    logger.debug(f"检测到特殊URL: {host} (模式: {url_pattern})")
                
                # 提取指定的头部
                header_name = special_config["extract_header"]
                header_pattern = re.compile(f'{header_name}:\\s*([^\\r\\n]+)', re.IGNORECASE)
                match = header_pattern.search(decoded_data)
                
                if match:
                    header_value = match.group(1).strip()
                    output_file = special_config["output_file"]
                    refresh_interval = special_config.get("refresh_interval", 0)  # 默认为0，表示总是更新
                    
                    if verbose_logging:
                        logger.info(f"找到 {header_name}: {header_value[:10]}...")
                    else:
                        logger.debug(f"找到 {header_name}")
                    
                    # 获取本地存储配置
                    local_storage_config = special_config.get("local_storage", {"enabled": True})
                    local_storage_enabled = local_storage_config.get("enabled", True)
                    
                    # 获取远程推送配置
                    remote_push_config = special_config.get("remote_push", {"enabled": False})
                    remote_push_enabled = remote_push_config.get("enabled", False)
                    
                    # 处理本地文件保存
                    if local_storage_enabled:
                        # 检查是否需要更新文件
                        should_update = True
                        if refresh_interval > 0 and os.path.exists(output_file):
                            file_mtime = os.path.getmtime(output_file)
                            current_time = time.time()
                            
                            # 计算文件存在的时间（分钟）
                            time_diff_minutes = (current_time - file_mtime) / 60
                            
                            if verbose_logging:
                                logger.info(f"文件上次修改时间: {datetime.datetime.fromtimestamp(file_mtime)}")
                                logger.info(f"当前时间: {datetime.datetime.fromtimestamp(current_time)}")
                                logger.info(f"文件已存在时间: {time_diff_minutes:.2f}分钟，刷新间隔: {refresh_interval}分钟")
                            
                            # 如果文件修改时间在刷新间隔内，则不更新
                            if time_diff_minutes < refresh_interval:
                                if verbose_logging:
                                    logger.info(f"文件 {output_file} 在刷新间隔内，跳过更新")
                                should_update = False
                            else:
                                if verbose_logging:
                                    logger.info(f"文件 {output_file} 已超过刷新间隔，将更新")
                        else:
                            if not os.path.exists(output_file):
                                if verbose_logging:
                                    logger.info(f"文件 {output_file} 不存在，将创建")
                            elif refresh_interval <= 0:
                                if verbose_logging:
                                    logger.info(f"刷新间隔设置为 {refresh_interval}，将始终更新")
                        
                        if should_update:
                            # 确保输出目录存在
                            os.makedirs(os.path.dirname(output_file), exist_ok=True)
                            
                            # 写入提取的值
                            with open(output_file, 'w', encoding='utf-8') as f:
                                f.write(header_value)
                            
                            if verbose_logging:
                                logger.info(f"已提取 {header_name} 并保存到 {output_file}")
                            else:
                                logger.debug(f"已更新 {output_file}")
                    elif verbose_logging:
                        logger.info("本地文件存储已禁用，跳过保存到文件")
                    
                    # 处理远程推送
                    if remote_push_enabled:
                        endpoints = remote_push_config.get("endpoints", [])
                        active_endpoints = [ep for ep in endpoints if ep.get("enabled", True)]
                        
                        if active_endpoints:
                            if verbose_logging:
                                logger.info(f"开始推送到 {len(active_endpoints)} 个已启用的远程接口")
                            
                            for endpoint in active_endpoints:
                                try:
                                    endpoint_name = endpoint.get("name", "未命名接口")
                                    url = endpoint.get("url")
                                    method = endpoint.get("method", "POST")
                                    headers = endpoint.get("headers", {})
                                    data_format = endpoint.get("data_format", '{"token": "$TOKEN"}')
                                    
                                    # 替换数据格式中的令牌占位符
                                    data_str = data_format.replace("$TOKEN", header_value)
                                    data = json.loads(data_str)
                                    
                                    if verbose_logging:
                                        logger.info(f"推送到接口 '{endpoint_name}': {url}")
                                        logger.info(f"请求方法: {method}")
                                        logger.info(f"请求头: {headers}")
                                        logger.info(f"请求数据: {json.dumps(data)[:100]}...")
                                    
                                    # 发送请求
                                    response = requests.request(
                                        method=method,
                                        url=url,
                                        headers=headers,
                                        json=data,
                                        timeout=10  # 设置超时时间
                                    )
                                    
                                    if response.status_code >= 200 and response.status_code < 300:
                                        if verbose_logging:
                                            logger.info(f"推送到 '{endpoint_name}' 成功: 状态码 {response.status_code}")
                                            logger.info(f"响应内容: {response.text[:100]}...")
                                        else:
                                            logger.debug(f"推送到 '{endpoint_name}' ({url}) 成功: 状态码 {response.status_code}")
                                    else:
                                        logger.warning(f"推送到 '{endpoint_name}' ({url}) 失败: 状态码 {response.status_code}")
                                        if verbose_logging:
                                            logger.warning(f"错误响应: {response.text[:200]}...")
                                except Exception as e:
                                    logger.error(f"推送到接口 '{endpoint.get('name', '未命名接口')}' ({endpoint.get('url')}) 时出错: {e}")
                        else:
                            logger.warning("启用了远程推送但所有端点都被禁用")
                    elif verbose_logging:
                        logger.info("远程推送功能已禁用")
                    
                # 再次使用分隔符结束
                if verbose_logging:
                    logger.info("\n" + "!"*80)
                    logger.info("特殊URL处理完成")
                    logger.info("!"*80 + "\n")
    except Exception as e:
        logger.error(f"处理特殊URL时出错: {e}")

def connect_through_proxy(target_host, target_port, config):
    """
    通过上游代理连接到目标服务器
    
    参数:
        target_host: 目标主机名
        target_port: 目标端口
        config: 配置字典
        
    返回:
        socket对象，已连接到目标服务器
    """
    if config["upstream_proxy"]["enabled"]:
        # 连接到上游代理
        proxy_host = config["upstream_proxy"]["host"]
        proxy_port = config["upstream_proxy"]["port"]
        
        logger.info(f"通过上游代理 {proxy_host}:{proxy_port} 连接到 {target_host}:{target_port}")
        
        # 创建到代理的连接
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.connect((proxy_host, proxy_port))
        
        # 发送CONNECT请求到代理
        connect_request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
        proxy_socket.sendall(connect_request.encode())
        
        # 读取代理响应
        response = proxy_socket.recv(1024)
        status_line = response.split(b'\r\n')[0].decode()
        
        if "200" not in status_line:  # 检查是否成功
            logger.error(f"上游代理连接失败: {status_line}")
            proxy_socket.close()
            raise Exception(f"上游代理连接失败: {status_line}")
            
        logger.info(f"已通过上游代理连接到 {target_host}:{target_port}")
        return proxy_socket
    else:
        # 直接连接到目标
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((target_host, target_port))
        return server_socket

def handle_client(client_socket, config):
    """
    处理客户端连接，支持HTTP和HTTPS请求
    
    参数:
        client_socket: 客户端socket
        config: 配置字典
    """
    try:
        # 接收客户端的请求
        request = client_socket.recv(1024)
        if not request:
            client_socket.close()
            return
        
        first_line = request.split(b'\r\n')[0].decode('utf-8')
        logger.info(f"收到请求: {first_line}")
        
        if first_line.startswith('CONNECT'):
            # 处理HTTPS请求
            _, address, _ = first_line.split(' ', 2)
            host, port = address.split(':', 1)
            port = int(port)
            
            # 告诉客户端连接已建立
            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            # 创建域名证书
            cert_file, key_file = create_domain_cert(host, config)
            
            # 创建SSL上下文
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            
            # 包装客户端socket
            client_ssl = context.wrap_socket(client_socket, server_side=True)
            
            # 通过上游代理连接到目标服务器
            server_socket = connect_through_proxy(host, port, config)
            
            # 与目标服务器建立SSL连接
            server_context = ssl.create_default_context()
            server_ssl = server_context.wrap_socket(server_socket, server_hostname=host)
            
            # 双向转发数据
            client_to_server = threading.Thread(
                target=forward_data, 
                args=(client_ssl, server_ssl, host, "请求", config)
            )
            server_to_client = threading.Thread(
                target=forward_data, 
                args=(server_ssl, client_ssl, host, "响应", config)
            )
            
            client_to_server.start()
            server_to_client.start()
            
            client_to_server.join()
            server_to_client.join()
        elif first_line.startswith('GET') or first_line.startswith('POST') or first_line.startswith('PUT') or first_line.startswith('DELETE') or first_line.startswith('HEAD'):
            # 处理HTTP请求
            method, url, _ = first_line.split(' ', 2)
            
            # 解析URL
            parsed_url = urllib.parse.urlparse(url)
            host = parsed_url.netloc
            path = parsed_url.path
            if not path:
                path = '/'
            if parsed_url.query:
                path += '?' + parsed_url.query
                
            # 如果没有指定端口，默认为80
            if ':' in host:
                host, port = host.split(':', 1)
                port = int(port)
            else:
                port = 80
                
            logger.info(f"HTTP请求: {method} {host}:{port}{path}")
            
            # 记录请求
            log_data("HTTP请求", host, request, config)
            
            # 通过上游代理连接到目标服务器
            server_socket = connect_through_proxy(host, port, config)
            
            # 修改请求头，将绝对URL改为相对URL
            modified_request = request.replace(url.encode(), path.encode(), 1)
            
            # 发送请求到目标服务器
            server_socket.sendall(modified_request)
            
            # 接收响应
            response = b''
            server_socket.settimeout(5)
            try:
                while True:
                    data = server_socket.recv(8192)
                    if not data:
                        break
                    response += data
            except socket.timeout:
                pass
            
            # 记录响应
            log_data("HTTP响应", host, response, config)
            
            # 发送响应给客户端
            client_socket.sendall(response)
            
            # 关闭连接
            server_socket.close()
            client_socket.close()
        else:
            logger.warning(f"不支持的请求类型: {first_line}")
            client_socket.close()
    except Exception as e:
        logger.error(f"处理客户端连接时出错: {e}")
        try:
            client_socket.close()
        except:
            pass

def forward_data(source, destination, host, direction, config):
    """
    转发数据并记录
    
    参数:
        source: 源socket
        destination: 目标socket
        host: 主机名
        direction: 数据方向，"请求"或"响应"
        config: 配置字典
    """
    try:
        buffer_size = 8192
        while True:
            try:
                data = source.recv(buffer_size)
                if not data:
                    break
                
                # 检查所有配置的特殊URL模式
                special_hosts = []
                for rule in config["header_extraction"]:
                    if isinstance(rule, dict) and "url_pattern" in rule:
                        url_pattern = rule["url_pattern"]
                        if "://" in url_pattern:
                            host_part = url_pattern.split("//")[1].split("/")[0]
                            special_hosts.append(host_part)
                
                if any(special_host in host for special_host in special_hosts):
                    try:
                        decoded = data.decode('utf-8', errors='replace')
                        logger.info(f"\n监控到匹配URL请求: {host} {direction}\n前100字符: {decoded[:100]}")
                    except:
                        pass
                
                # 记录数据
                log_data(direction, host, data, config)
                
                # 转发数据
                destination.sendall(data)
            except ssl.SSLError as e:
                if e.args[0] == ssl.SSL_ERROR_WANT_READ:
                    continue
                else:
                    logger.error(f"SSL错误: {e}")
                    break
            except Exception as e:
                logger.error(f"转发数据时出错: {e}")
                break
    finally:
        try:
            source.close()
        except:
            pass
        try:
            destination.close()
        except:
            pass

def check_config_changes(config_file="config.yaml", current_config=None):
    """
    检查配置文件是否有变更
    
    参数:
        config_file: 配置文件路径
        current_config: 当前配置字典
        
    返回:
        如果有变更，返回新的配置字典；否则返回None
    """
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                new_config = yaml.safe_load(f)
            
            # 检查是否有变更
            if new_config != current_config:
                logger.info("检测到配置文件变更，重新加载配置")
                
                # 递归更新配置
                def update_config(default, user):
                    for key, value in user.items():
                        if isinstance(value, dict) and key in default:
                            update_config(default[key], value)
                        else:
                            default[key] = value
                
                # 创建配置副本
                updated_config = copy.deepcopy(current_config)
                update_config(updated_config, new_config)
                
                return updated_config
    except Exception as e:
        logger.error(f"检查配置文件变更时出错: {e}")
    
    return None

def main():
    """主函数，启动代理服务器"""
    global logger, CONFIG
    
    # 加载配置
    CONFIG = load_config()
    
    # 设置日志
    logger = setup_logging(CONFIG)
    
    # 创建CA证书
    create_ca_cert(CONFIG)
    
    # 创建代理服务器
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((CONFIG["proxy"]["host"], CONFIG["proxy"]["port"]))
    server.listen(100)
    
    logger.info(f"代理服务器运行在 {CONFIG['proxy']['host']}:{CONFIG['proxy']['port']}")
    logger.info("请确保CA证书已被系统/浏览器信任")
    
    # 启动配置检查线程
    if CONFIG.get("realtime_config", {}).get("enabled", False):
        check_interval = CONFIG.get("realtime_config", {}).get("check_interval", 10)
        config_thread = threading.Thread(target=config_check_loop, args=(check_interval,))
        config_thread.daemon = True
        config_thread.start()
        logger.info(f"实时配置检查已启用，间隔: {check_interval}秒")
    
    try:
        while True:
            client_socket, addr = server.accept()
            logger.info(f"接受来自 {addr} 的连接")
            
            client_thread = threading.Thread(target=handle_client, args=(client_socket, CONFIG))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        logger.info("代理服务器正在关闭...")
    finally:
        server.close()

def config_check_loop(interval):
    """
    配置检查循环，定期检查配置文件变更
    
    参数:
        interval: 检查间隔（秒）
    """
    global CONFIG, logger
    
    while True:
        time.sleep(interval)
        new_config = check_config_changes("config.yaml", CONFIG)
        if new_config:
            # 更新全局配置
            CONFIG = new_config
            # 更新日志设置
            logger = setup_logging(CONFIG)
            logger.info("配置已更新")

if __name__ == "__main__":
    main() 