#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import random
import time
import shutil
import re
import base64
import socket
import subprocess
import platform
from datetime import datetime
import uuid
from pathlib import Path
import urllib.request
import ssl
import tempfile
import streamlit as st

# 全局变量
INSTALL_DIR = Path.home() / ".agsb"  # 用户主目录下的隐藏文件夹
CONFIG_FILE = INSTALL_DIR / "config.json"
SB_PID_FILE = INSTALL_DIR / "sbpid.log"
ARGO_PID_FILE = INSTALL_DIR / "sbargopid.log"
LIST_FILE = INSTALL_DIR / "list.txt"
LOG_FILE = INSTALL_DIR / "argo.log"
DEBUG_LOG = INSTALL_DIR / "python_debug.log"
CUSTOM_DOMAIN_FILE = INSTALL_DIR / "custom_domain.txt"

# ====== 全局参数（将由用户在Streamlit界面输入） ======
# 已清空所有硬编码的敏感信息
USER_NAME = ""
UUID = ""
PORT = 0
DOMAIN = ""
CF_TOKEN = ""
# =======================================================

# --- Helper Functions ---

def strip_ansi_codes(text):
    """移除文本中的ANSI颜色代码"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def write_debug_log(message):
    try:
        if not INSTALL_DIR.exists():
            INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        with open(DEBUG_LOG, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass # 在st环境中，文件权限可能受限

def http_get(url, timeout=10):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        write_debug_log(f"HTTP GET Error: {url}, {e}")
        return None

def download_file(url, target_path, mode='wb'):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=ctx) as response, open(target_path, mode) as out_file:
            shutil.copyfileobj(response, out_file)
        return True
    except Exception as e:
        write_debug_log(f"Download Error: {url}, {e}")
        return False

def generate_vmess_link(config):
    vmess_obj = {
        "v": "2", "ps": config.get("ps", "ArgoSB"), "add": config.get("add", ""),
        "port": str(config.get("port", "443")), "id": config.get("id", ""), "aid": "0",
        "net": "ws", "type": "none", "host": config.get("host", ""), "path": config.get("path", ""),
        "tls": config.get("tls", "tls"), "sni": config.get("sni", "")
    }
    vmess_str = json.dumps(vmess_obj, sort_keys=True)
    vmess_b64 = base64.b64encode(vmess_str.encode('utf-8')).decode('utf-8').rstrip("=")
    return f"vmess://{vmess_b64}"

def get_tunnel_domain():
    retry_count = 0
    max_retries = 15
    while retry_count < max_retries:
        if LOG_FILE.exists():
            try:
                log_content = LOG_FILE.read_text()
                match = re.search(r'https://([a-zA-Z0-9.-]+\.trycloudflare\.com)', log_content)
                if match:
                    domain = match.group(1)
                    return domain
            except Exception as e:
                write_debug_log(f"读取或解析日志文件 {LOG_FILE} 出错: {e}")
        retry_count += 1
        time.sleep(2)
    return None

def upload_to_api(subscription_content, user_name):
    # This function is kept for users who explicitly opt-in.
    UPLOAD_API = "https://file.zmkk.fun/api/upload"
    try:
        import requests
    except ImportError:
        return False, "缺少 'requests' 库，无法上传。请手动安装：pip install requests"

    try:
        file_name = f"{user_name or 'subscription'}.txt"
        files = {'file': (file_name, subscription_content, 'text/plain')}
        response = requests.post(UPLOAD_API, files=files)

        if response.status_code == 200:
            result = response.json()
            if result.get('success') or result.get('url'):
                url = result.get('url', '')
                return True, f"订阅上传成功！URL: {url}"
            else:
                return False, f"API 返回错误: {result}"
        else:
            return False, f"上传失败，状态码: {response.status_code}"
    except Exception as e:
        return False, f"上传过程中出错: {e}"


# --- Core Logic Functions (Modified for Streamlit) ---

def generate_links_modified(domain, port_vm_ws, uuid_str):
    output = []
    ws_path = f"/{uuid_str[:8]}-vm"
    ws_path_full = f"{ws_path}?ed=2048"
    hostname = socket.gethostname()[:10]
    all_links = []
    
    # ... (link generation logic from original script, unchanged)
    cf_ips_tls = {"104.16.0.0": "443", "104.17.0.0": "8443", "104.18.0.0": "2053", "104.19.0.0": "2083", "104.20.0.0": "2087"}
    cf_ips_http = {"104.21.0.0": "80", "104.22.0.0": "8080", "104.24.0.0": "8880"}
    
    for ip, port in cf_ips_tls.items():
        all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-{hostname}-{ip.split('.')[2]}-{port}", "add": ip, "port": port, "id": uuid_str, "host": domain, "path": ws_path_full, "tls": "tls", "sni": domain}))
    for ip, port in cf_ips_http.items():
        all_links.append(generate_vmess_link({"ps": f"VMWS-HTTP-{hostname}-{ip.split('.')[2]}-{port}", "add": ip, "port": port, "id": uuid_str, "host": domain, "path": ws_path_full, "tls": ""}))
    all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-Direct-{hostname}", "add": domain, "port": "443", "id": uuid_str, "host": domain, "path": ws_path_full, "tls": "tls", "sni": domain}))
    all_links.append(generate_vmess_link({"ps": f"VMWS-HTTP-Direct-{hostname}", "add": domain, "port": "80", "id": uuid_str, "host": domain, "path": ws_path_full, "tls": ""}))

    (INSTALL_DIR / "allnodes.txt").write_text("\n".join(all_links) + "\n")
    CUSTOM_DOMAIN_FILE.write_text(domain)
    
    # Prepare output for display
    output.append("✨ ArgoSB 安装成功! ✨")
    output.append("────────────────────────────────")
    output.append(f"域名 (Domain): {domain}")
    output.append(f"UUID: {uuid_str}")
    output.append(f"本地Vmess端口: {port_vm_ws}")
    output.append(f"WebSocket路径: {ws_path_full}")
    output.append("────────────────────────────────")
    output.append("所有节点链接 (可直接复制):")
    output.extend(all_links)
    
    # Save detailed info to list.txt without colors
    list_content = "\n".join(output)
    LIST_FILE.write_text(list_content)
    
    return "\n".join(output), "\n".join(all_links)

def install_modified(user_name, uuid_str, port_vm_ws, custom_domain, argo_token, enable_upload):
    output_log = []
    
    try:
        if not INSTALL_DIR.exists():
            INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        os.chdir(INSTALL_DIR)
        
        # --- Validate and Finalize Config ---
        user_name = user_name or "argo-user"
        uuid_str = uuid_str or str(uuid.uuid4())
        if not port_vm_ws or port_vm_ws == 0:
            port_vm_ws = random.randint(10000, 65535)

        output_log.append(f"使用配置:\n- 用户名: {user_name}\n- UUID: {uuid_str}\n- Vmess端口: {port_vm_ws}")
        if custom_domain: output_log.append(f"- 自定义域名: {custom_domain}")
        if argo_token: output_log.append("- 使用 Argo Tunnel Token")

        # --- Download Binaries ---
        system = platform.system().lower()
        machine = platform.machine().lower()
        arch = "amd64" if "x86_64" in machine else "arm64" if "aarch64" in machine else "amd64"
        
        # Download sing-box if not exists
        singbox_path = INSTALL_DIR / "sing-box"
        if not singbox_path.exists():
            output_log.append("正在下载 sing-box...")
            sb_version = "1.9.0-beta.11" # Using a fixed version for stability
            sb_name_actual = f"sing-box-{sb_version}-linux-{arch}"
            if arch == "arm": sb_name_actual = f"sing-box-{sb_version}-linux-armv7"
            sb_url = f"https://github.com/SagerNet/sing-box/releases/download/v{sb_version}/{sb_name_actual}.tar.gz"
            tar_path = INSTALL_DIR / "sing-box.tar.gz"
            if not download_file(sb_url, tar_path):
                return False, "\n".join(output_log) + "\n\n错误: sing-box 下载失败。"
            import tarfile
            with tarfile.open(tar_path, "r:gz") as tar: tar.extractall(path=INSTALL_DIR)
            shutil.move(INSTALL_DIR / sb_name_actual / "sing-box", singbox_path)
            shutil.rmtree(INSTALL_DIR / sb_name_actual)
            tar_path.unlink()
            os.chmod(singbox_path, 0o755)
            output_log.append("sing-box 下载并解压成功！")

        # Download cloudflared if not exists
        cloudflared_path = INSTALL_DIR / "cloudflared"
        if not cloudflared_path.exists():
            output_log.append("正在下载 cloudflared...")
            cf_arch = "arm" if arch == "armv7" else arch
            cf_url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}"
            if not download_file(cf_url, cloudflared_path):
                 return False, "\n".join(output_log) + "\n\n错误: cloudflared 下载失败。"
            os.chmod(cloudflared_path, 0o755)
            output_log.append("cloudflared 下载成功！")

        # --- Create Configs and Scripts ---
        config_data = { "user_name": user_name, "uuid_str": uuid_str, "port_vm_ws": port_vm_ws, "argo_token": argo_token, "custom_domain_agn": custom_domain }
        CONFIG_FILE.write_text(json.dumps(config_data, indent=2))
        
        # Create sing-box config
        ws_path = f"/{uuid_str[:8]}-vm"
        sb_config = {"log": {"level": "info"}, "inbounds": [{"type": "vmess", "listen": "127.0.0.1", "listen_port": port_vm_ws, "users": [{"uuid": uuid_str, "alterId": 0}], "transport": {"type": "ws", "path": ws_path, "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}}], "outbounds": [{"type": "direct"}]}
        (INSTALL_DIR / "sb.json").write_text(json.dumps(sb_config, indent=2))

        # Create startup scripts
        (INSTALL_DIR / "start_sb.sh").write_text(f'#!/bin/bash\ncd {INSTALL_DIR.resolve()}\n./sing-box run -c sb.json > sb.log 2>&1 &\necho $! > {SB_PID_FILE.name}\n')
        os.chmod(INSTALL_DIR / "start_sb.sh", 0o755)
        
        ws_path_full = f"{ws_path}?ed=2048"
        if argo_token:
            cf_cmd = f"./cloudflared tunnel --no-autoupdate run --token {argo_token}"
        else:
            cf_cmd = f"./cloudflared tunnel --no-autoupdate --url http://localhost:{port_vm_ws}{ws_path_full} --edge-ip-version auto --protocol http2"
        
        (INSTALL_DIR / "start_cf.sh").write_text(f'#!/bin/bash\ncd {INSTALL_DIR.resolve()}\n{cf_cmd} > {LOG_FILE.name} 2>&1 &\necho $! > {ARGO_PID_FILE.name}\n')
        os.chmod(INSTALL_DIR / "start_cf.sh", 0o755)

        # --- Start Services ---
        output_log.append("正在启动服务...")
        subprocess.run(str(INSTALL_DIR / "start_sb.sh"), shell=True)
        subprocess.run(str(INSTALL_DIR / "start_cf.sh"), shell=True)
        output_log.append("服务启动命令已发送，等待5秒...")
        time.sleep(5)

        # --- Get Domain and Generate Links ---
        final_domain = custom_domain
        if not argo_token and not custom_domain:
            output_log.append("正在获取临时隧道域名...")
            final_domain = get_tunnel_domain()
            if not final_domain:
                return False, "\n".join(output_log) + "\n\n错误: 无法获取隧道域名。请检查日志或尝试手动指定域名。"
        
        if final_domain:
            links_output, all_links_str = generate_links_modified(final_domain, port_vm_ws, uuid_str)
            output_log.append("\n" + links_output)
            
            # --- Handle Optional Upload ---
            if enable_upload:
                output_log.append("\n正在上传到订阅服务器...")
                all_links_b64 = base64.b64encode(all_links_str.encode()).decode()
                success, message = upload_to_api(all_links_b64, user_name)
                output_log.append(message)
        else:
            return False, "\n".join(output_log) + "\n\n错误: 最终域名未能确定，无法生成链接。"

        return True, "\n".join(output_log)

    except Exception as e:
        write_debug_log(f"Installation failed: {e}")
        return False, "\n".join(output_log) + f"\n\n发生意外错误: {e}"

def uninstall_modified():
    output_log = []
    output_log.append("开始卸载服务...")
    
    # Stop processes by PID
    for pid_file in [SB_PID_FILE, ARGO_PID_FILE]:
        if pid_file.exists():
            try:
                pid = pid_file.read_text().strip()
                if pid:
                    subprocess.run(f"kill {pid}", shell=True, capture_output=True)
                    output_log.append(f"已停止进程 PID: {pid}")
            except Exception:
                pass
    time.sleep(1)

    # Force kill remaining processes
    subprocess.run("pkill -9 -f 'sing-box run'", shell=True)
    subprocess.run("pkill -9 -f 'cloudflared tunnel'", shell=True)
    output_log.append("已强制终止残留进程。")

    # Remove installation directory
    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
        output_log.append(f"安装目录 {INSTALL_DIR} 已删除。")
    
    output_log.append("卸载完成。")
    return "\n".join(output_log)

def check_status_modified():
    if not INSTALL_DIR.exists() or not CONFIG_FILE.exists():
        return "服务未安装。"
        
    output_lines = []
    
    try:
        sb_pid = SB_PID_FILE.read_text().strip() if SB_PID_FILE.exists() else None
        cf_pid = ARGO_PID_FILE.read_text().strip() if ARGO_PID_FILE.exists() else None
        
        sb_running = sb_pid and os.path.exists(f"/proc/{sb_pid}")
        cf_running = cf_pid and os.path.exists(f"/proc/{cf_pid}")

        if sb_running and cf_running:
            output_lines.append("✅ 服务状态: 正在运行 (sing-box & cloudflared)")
            if LIST_FILE.exists():
                output_lines.append("\n" + LIST_FILE.read_text())
            else:
                output_lines.append("节点信息文件未找到，可能正在生成中。")
        else:
            output_lines.append("❌ 服务状态: 异常")
            if not sb_running: output_lines.append("  - sing-box 未运行")
            if not cf_running: output_lines.append("  - cloudflared 未运行")
            output_lines.append("\n请尝试重新安装或检查日志。")

    except Exception as e:
        output_lines.append(f"检查状态时出错: {e}")

    return "\n".join(output_lines)


# --- Streamlit UI ---

def main_streamlit():
    st.set_page_config(page_title="ArgoSB 部署工具", layout="wide")
    st.title("✨ ArgoSB 一键部署与管理面板 ✨")
    st.caption("一个通过图形化界面部署和管理 sing-box + cloudflared 代理的工具")

    if 'output' not in st.session_state:
        st.session_state.output = check_status_modified()

    # --- Layout ---
    col1, col2 = st.columns([1, 1])

    with col1:
        st.header("⚙️ 安装配置")
        with st.expander("点击展开配置项", expanded=True):
            st.info("请填写配置。留空将使用默认或随机值。")
            user_name = st.text_input("用户名 (用于备注)", help="仅用于节点名称，保护隐私")
            uuid_str = st.text_input("UUID", help="留空将自动生成一个随机UUID")
            port_vm_ws = st.number_input("Vmess 本地端口", min_value=0, max_value=65535, value=0, help="1024-65535之间的端口，留空或0则随机")
            custom_domain = st.text_input("自定义域名", help="使用命名隧道时必需，例如 my.domain.com")
            argo_token = st.text_input("Argo Tunnel Token", type="password", help="使用命名隧道时提供，否则请留空以使用临时隧道")
            
            st.markdown("---")
            st.warning("隐私提示：以下功能会将您的节点信息发送到第三方服务器。")
            enable_upload = st.checkbox("允许上传到 file.zmkk.fun 生成订阅链接", help="勾选此项表示您了解并接受将节点配置发送到第三方服务器的风险。")

    with col2:
        st.header("🚀 操作与状态")
        
        # Action Buttons
        btn_col1, btn_col2, btn_col3 = st.columns(3)
        with btn_col1:
            install_button = st.button("✅ 安装/启动", use_container_width=True)
        with btn_col2:
            uninstall_button = st.button("❌ 卸载服务", type="primary", use_container_width=True)
        with btn_col3:
            status_button = st.button("🔄 刷新状态", use_container_width=True)

        st.subheader("📋 状态与节点信息")
        output_placeholder = st.empty()
        output_placeholder.text_area("输出日志", st.session_state.output, height=400)

    # --- Button Logic ---
    if install_button:
        with st.spinner("正在执行安装/启动流程，请稍候..."):
            success, message = install_modified(user_name, uuid_str, port_vm_ws, custom_domain, argo_token, enable_upload)
            if success:
                st.success("操作成功完成！")
            else:
                st.error("操作失败！请检查输出日志。")
            st.session_state.output = message
            output_placeholder.text_area("输出日志", st.session_state.output, height=400)
            st.experimental_rerun()


    if uninstall_button:
        with st.spinner("正在卸载服务..."):
            message = uninstall_modified()
            st.success("卸载操作完成！")
            st.session_state.output = message
            output_placeholder.text_area("输出日志", st.session_state.output, height=400)
            st.experimental_rerun()

    if status_button:
        st.session_state.output = check_status_modified()
        output_placeholder.text_area("输出日志", st.session_state.output, height=400)
        st.success("状态已刷新。")


if __name__ == "__main__":
    # This script is intended to be run with Streamlit.
    # The original command-line interface is removed for clarity.
    # To run: streamlit run your_script_name.py
    main_streamlit()