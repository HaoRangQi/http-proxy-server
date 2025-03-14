# HTTPS中间人代理服务器

这是一个功能完整的HTTPS中间人代理服务器，可以拦截、记录和修改HTTP/HTTPS流量。主要用于提取特定API请求中的授权令牌，并支持通过上游代理转发请求。

## 主要功能

1. **HTTP/HTTPS请求拦截**：支持拦截和处理HTTP和HTTPS请求
2. **动态证书生成**：自动为访问的域名生成证书，实现HTTPS中间人代理
3. **令牌提取**：从特定URL的请求中提取授权令牌并保存到文件
4. **上游代理支持**：可以将所有请求通过上游代理（如Clash）转发
5. **实时配置更新**：支持在不重启服务器的情况下更新配置
6. **详细日志记录**：可配置的日志级别和请求记录功能

## 安装和依赖

### 依赖项

- Python 3.6+
- PyOpenSSL
- PyYAML

### 安装依赖

```bash
pip install pyopenssl pyyaml
```

## 使用方法

1. **启动代理服务器**：

```bash
python https_proxy.py
```

2. **配置浏览器或系统使用代理**：

默认代理地址为 `127.0.0.1:6000`

3. **安装CA证书**：

首次运行时，程序会在`certs`目录下生成CA证书（`proxy_ca.crt`）。你需要将此证书安装到系统或浏览器的信任列表中。

### macOS安装证书：

1. 双击`certs/proxy_ca.crt`文件
2. 在"钥匙串访问"中找到证书
3. 双击证书，展开"信任"部分
4. 将"使用此证书时"选项更改为"始终信任"
5. 关闭窗口，输入管理员密码确认

### Windows安装证书：

1. 双击`certs/proxy_ca.crt`文件
2. 点击"安装证书"
3. 选择"本地计算机"，点击"下一步"
4. 选择"将所有证书放入下列存储"，点击"浏览"
5. 选择"受信任的根证书颁发机构"，点击"确定"
6. 点击"下一步"，然后点击"完成"

## 配置文件

配置文件`config.yaml`包含以下主要部分：

### 代理服务器配置

```yaml
proxy:
  host: 127.0.0.1  # 代理服务器监听地址
  port: 6000       # 代理服务器监听端口
```

### 日志配置

```yaml
logging:
  level: INFO      # 日志级别: DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: proxy.log  # 日志文件路径
```

### 证书配置

```yaml
certificates:
  dir: certs                # 证书存储目录
  name_prefix: "proxy_"     # 证书文件名前缀
```

### 请求头处理配置

```yaml
header_extraction:
  - name: "API认证提取"
    url_pattern: "https://api.example.com/completion"  # 要监控的URL
    extract_header: "Authorization"                    # 要提取的请求头
    output_file: "auth/api_tokens.txt"                 # 提取内容保存路径
    refresh_interval: 30                               # 刷新间隔（分钟）
    verbose_logging: false                             # 是否打印详细日志
```

### 上游代理配置

```yaml
upstream_proxy:
  enabled: true     # 是否使用上游代理
  host: 127.0.0.1   # 上游代理地址（如Clash）
  port: 7890        # 上游代理端口
```

### 实时配置更新

```yaml
realtime_config:
  enabled: true     # 是否启用实时配置更新
  check_interval: 10  # 检查配置文件变更的间隔（秒）
```

## 实时配置修改

你可以在代理服务器运行时修改配置文件，更改会自动应用，无需重启服务器。例如：

1. 修改`header_extraction`规则的`verbose_logging`为`true`，可以查看详细的请求日志
2. 修改`upstream_proxy.enabled`为`false`，可以禁用上游代理
3. 修改`recording.enabled`为`true`，可以记录所有请求和响应内容

## 提取的令牌

从特定URL提取的授权令牌会保存在配置的`output_file`路径中。程序会根据配置的刷新间隔自动更新此文件。

## 故障排除

### 证书问题

如果遇到SSL错误，请确保：
- CA证书已正确安装到系统/浏览器的信任列表中
- 证书目录有正确的读写权限
- 证书名称前缀与配置文件一致

### 连接问题

如果无法连接到目标服务器：
- 检查上游代理配置是否正确
- 确认上游代理（如Clash）是否正在运行
- 查看日志文件获取详细错误信息

## 安全注意事项

此代理服务器实现了HTTPS中间人攻击技术，仅用于合法的开发和测试目的。请勿用于未经授权的网络监控或攻击行为。

## 许可证

MIT
