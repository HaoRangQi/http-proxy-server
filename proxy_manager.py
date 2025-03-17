#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
HTTP代理服务器管理脚本
功能: 启动、停止、重启和监控代理服务器状态
"""

import os
import sys
import time
import argparse
import subprocess
import signal
from pathlib import Path

# 检查是否安装了psutil
try:
    import psutil
except ImportError:
    print("错误: 缺少psutil模块")
    print("请运行以下命令安装: pip install psutil")
    print("安装后重新运行此脚本")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("错误: 缺少yaml模块")
    print("请运行以下命令安装: pip install pyyaml")
    print("安装后重新运行此脚本")
    sys.exit(1)

# 获取当前脚本的绝对路径
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PID_FILE = os.path.join(SCRIPT_DIR, "proxy.pid")
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.yaml")
PROXY_SCRIPT = os.path.join(SCRIPT_DIR, "https_proxy.py")
LOG_FILE = os.path.join(SCRIPT_DIR, "proxy.log")


def load_config():
    """加载配置文件"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"无法加载配置文件: {e}")
        return None


def get_server_port():
    """从配置文件获取服务器端口"""
    config = load_config()
    if config and 'proxy' in config and 'port' in config['proxy']:
        return config['proxy']['port']
    return 6000  # 默认端口


def is_running():
    """检查代理服务器是否正在运行"""
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            
            # 检查进程是否存在
            if psutil.pid_exists(pid):
                process = psutil.Process(pid)
                # 验证这是我们的代理进程
                if "python" in process.name().lower() and any("https_proxy" in cmd for cmd in process.cmdline()):
                    return pid
            
            # 如果到这里，PID文件存在但进程不存在或不是代理进程
            os.remove(PID_FILE)
        except Exception as e:
            print(f"检查进程状态时出错: {e}")
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
    
    return None


def start_server():
    """启动代理服务器"""
    pid = is_running()
    if pid:
        print(f"代理服务器已经在运行 (PID: {pid})")
        return False
    
    try:
        # 启动服务器进程
        process = subprocess.Popen(
            [sys.executable, PROXY_SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=SCRIPT_DIR,
            start_new_session=True  # 使进程独立运行
        )
        
        # 写入PID文件
        with open(PID_FILE, 'w') as f:
            f.write(str(process.pid))
        
        port = get_server_port()
        print(f"代理服务器已启动 (PID: {process.pid}, 端口: {port})")
        return True
    except Exception as e:
        print(f"启动服务器失败: {e}")
        return False


def stop_server():
    """停止代理服务器"""
    pid = is_running()
    if not pid:
        print("代理服务器未运行")
        return False
    
    try:
        # 尝试优雅地终止进程
        os.kill(pid, signal.SIGTERM)
        
        # 等待进程终止
        for _ in range(5):
            if not psutil.pid_exists(pid):
                break
            time.sleep(1)
        
        # 如果进程仍在运行，强制终止
        if psutil.pid_exists(pid):
            os.kill(pid, signal.SIGKILL)
            print(f"强制终止代理服务器进程 (PID: {pid})")
        else:
            print(f"代理服务器已停止 (PID: {pid})")
        
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        
        return True
    except Exception as e:
        print(f"停止服务器失败: {e}")
        return False


def restart_server():
    """重启代理服务器"""
    if is_running():
        if stop_server():
            time.sleep(2)  # 等待资源释放
            return start_server()
        return False
    else:
        return start_server()


def server_status():
    """显示服务器状态"""
    pid = is_running()
    if not pid:
        print("代理服务器状态: 未运行")
        return
    
    # 获取进程信息
    try:
        process = psutil.Process(pid)
        create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(process.create_time()))
        
        # 获取CPU和内存使用情况
        cpu_percent = process.cpu_percent(interval=0.5)
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / 1024 / 1024
        
        # 获取连接信息
        connections = len(process.connections())
        
        # 获取最新日志
        last_log_lines = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
                last_log_lines = lines[-5:] if len(lines) > 5 else lines
        
        # 显示状态信息
        port = get_server_port()
        print(f"代理服务器状态: 运行中")
        print(f"PID: {pid}")
        print(f"端口: {port}")
        print(f"启动时间: {create_time}")
        print(f"运行时长: {time.time() - process.create_time():.1f}秒")
        print(f"CPU使用率: {cpu_percent:.1f}%")
        print(f"内存使用: {memory_mb:.2f} MB")
        print(f"活动连接: {connections}")
        
        if last_log_lines:
            print("\n最近日志:")
            for line in last_log_lines:
                print(f"  {line.strip()}")
        
    except Exception as e:
        print(f"获取服务器状态时出错: {e}")


def tail_log(lines=10):
    """显示日志文件的最后几行"""
    if not os.path.exists(LOG_FILE):
        print(f"日志文件不存在: {LOG_FILE}")
        return
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
            all_lines = f.readlines()
            last_lines = all_lines[-lines:] if len(all_lines) >= lines else all_lines
        
        print(f"\n=== 最近 {len(last_lines)} 行日志 ===")
        for line in last_lines:
            print(line.strip())
    except Exception as e:
        print(f"读取日志失败: {e}")


def view_tokens():
    """查看当前的API令牌"""
    token_file = os.path.join(SCRIPT_DIR, "auth/api_tokens.txt")
    if not os.path.exists(token_file):
        print("令牌文件不存在")
        return
    
    try:
        with open(token_file, 'r', encoding='utf-8', errors='replace') as f:
            token = f.read().strip()
        
        if token:
            # 只显示令牌的一部分，保护敏感信息
            print(f"API令牌: {token[:10]}...{token[-5:] if len(token) > 15 else ''}")
            print(f"令牌长度: {len(token)}字符")
            print(f"最后更新时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(token_file)))}")
        else:
            print("令牌文件为空")
    except Exception as e:
        print(f"读取令牌文件失败: {e}")


def delete_token():
    """删除API令牌文件"""
    token_file = os.path.join(SCRIPT_DIR, "auth/api_tokens.txt")
    if not os.path.exists(token_file):
        print("令牌文件不存在，无需删除")
        return
    
    try:
        os.remove(token_file)
        print(f"令牌文件已成功删除: {token_file}")
    except Exception as e:
        print(f"删除令牌文件失败: {e}")


def show_menu():
    """显示交互式菜单"""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("=" * 50)
        print("       HTTP代理服务器管理工具")
        print("=" * 50)
        
        # 获取当前状态
        running = is_running()
        status_text = f"运行中 (PID: {running})" if running else "未运行"
        
        print(f"当前状态: {status_text}")
        if running:
            port = get_server_port()
            print(f"监听端口: {port}")
        print("-" * 50)
        
        print("1. 启动代理服务器")
        print("2. 停止代理服务器")
        print("3. 重启代理服务器")
        print("4. 查看详细状态")
        print("5. 查看服务器日志")
        print("6. 查看API令牌")
        print("7. 删除API令牌")
        print("0. 退出")
        
        choice = input("\n请选择操作 [0-7]: ")
        
        if choice == '1':
            start_server()
            input("\n按Enter继续...")
        elif choice == '2':
            stop_server()
            input("\n按Enter继续...")
        elif choice == '3':
            restart_server()
            input("\n按Enter继续...")
        elif choice == '4':
            server_status()
            input("\n按Enter继续...")
        elif choice == '5':
            lines = input("要显示多少行日志？[默认10]: ")
            try:
                lines = int(lines) if lines.strip() else 10
            except ValueError:
                lines = 10
            tail_log(lines)
            input("\n按Enter继续...")
        elif choice == '6':
            view_tokens()
            input("\n按Enter继续...")
        elif choice == '7':
            confirm = input("确定要删除API令牌文件吗？(y/n): ")
            if confirm.lower() == 'y':
                delete_token()
            else:
                print("已取消删除操作")
            input("\n按Enter继续...")
        elif choice == '0':
            print("退出程序...")
            break
        else:
            print("无效选择，请重试")
            time.sleep(1)


def main():
    """主函数，处理命令行参数或显示交互式菜单"""
    # 检查是否有命令行参数
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description='HTTP代理服务器管理工具')
        parser.add_argument('action', choices=['start', 'stop', 'restart', 'status', 'log', 'menu'],
                            help='执行的操作: start=启动, stop=停止, restart=重启, status=状态, log=查看日志, menu=交互菜单')
        parser.add_argument('--lines', type=int, default=10,
                            help='显示日志的行数 (默认: 10)')
        
        args = parser.parse_args()
        
        # 根据命令行参数执行相应的操作
        if args.action == 'start':
            start_server()
        elif args.action == 'stop':
            stop_server()
        elif args.action == 'restart':
            restart_server()
        elif args.action == 'status':
            server_status()
        elif args.action == 'log':
            tail_log(args.lines)
        elif args.action == 'menu':
            show_menu()
    else:
        # 如果没有命令行参数，显示交互式菜单
        show_menu()


if __name__ == "__main__":
    main()