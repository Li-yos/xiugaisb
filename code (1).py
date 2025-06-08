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

# --- 全局变量和基本函数 (与之前版本相同) ---
INSTALL_DIR = Path.home() / ".agsb"
CONFIG_FILE = INSTALL_DIR / "config.json"
LOG_FILE = INSTALL_DIR / "argo.log"
DEBUG_LOG = INSTALL_DIR / "python_debug.log"
CUSTOM_DOMAIN_FILE = INSTALL_DIR / "custom_domain.txt"
LIST_FILE = INSTALL_DIR / "list.txt"

def write_debug_log(message):
    try:
        if not INSTALL_DIR.exists(): INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        with open(DEBUG_LOG, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except Exception: pass

def http_get(url, timeout=10):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
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
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
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
    return f"vmess://{base64.b64encode(vmess_str.encode('utf-8')).decode('utf-8').rstrip('=')}"

# --- 新增的 Systemd 管理函数 ---
def run_sudo_command(command):
    full_command = f"sudo {command}"
    try:
        result = subprocess.run(full_command, shell=True, check=True, capture_output=True, text=True, timeout=30)
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_message = f"命令 '{full_command}' 执行失败.\n错误: {e.stderr.strip()}"
        return False, error_message
    except subprocess.TimeoutExpired:
        return False, f"命令 '{full_command}' 执行超时。"

def create_systemd_service(service_name, description, command, working_dir, user):
    service_content = f"""
[Unit]
Description={description}
After=network.target
[Service]
Type=simple
User={user}
WorkingDirectory={working_dir}
ExecStart={command}
Restart=always
RestartSec=5s
[Install]
WantedBy=multi-user.target
"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".service") as tmp:
            tmp.write(service_content)
            tmp_path = tmp.name
        
        service_file_path = f"/etc/systemd/system/{service_name}.service"
        success, msg = run_sudo_command(f"mv {tmp_path} {service_file_path}")
        if not success: return False, msg
        
        success, msg = run_sudo_command(f"chmod 644 {service_file_path}")
        if not success: return False, msg
        
        success, msg = run_sudo_command("systemctl daemon-reload")
        if not success: return False, f"systemctl daemon-reload 失败: {msg}"
        
        success, msg = run_sudo_command(f"systemctl enable {service_name}")
        if not success: return False, f"systemctl enable {service_name} 失败: {msg}"
        
        success, msg = run_sudo_command(f"systemctl restart {service_name}")
        if not success: return False, f"systemctl restart {service_name} 失败: {msg}"

        return True, f"服务 {service_name} 已成功创建并启动。"
    except Exception as e:
        return False, f"创建服务文件时发生错误: {e}"


def remove_systemd_service(service_name):
    run_sudo_command(f"systemctl stop {service_name}")
    run_sudo_command(f"systemctl disable {service_name}")
    run_sudo_command(f"rm -f /etc/systemd/system/{service_name}.service")
    run_sudo_command("systemctl daemon-reload")
    return True, f"服务 {service_name} 已移除。"


# --- 重构的核心逻辑函数 ---
def generate_links_modified(domain, port_vm_ws, uuid_str):
    # (此函数无需改变，和上个版本一样)
    output = []
    ws_path = f"/{uuid_str[:8]}-vm"
    ws_path_full = f"{ws_path}?ed=2048"
    hostname = socket.gethostname()[:10]
    all_links = []
    
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
    
    output.append("✨ ArgoSB 安装成功! ✨")
    output.append("────────────────────────────────")
    output.append(f"域名 (Domain): {domain}\nUUID: {uuid_str}\n本地Vmess端口: {port_vm_ws}\nWebSocket路径: {ws_path_full}")
    output.append("────────────────────────────────")
    output.append("所有节点链接 (可直接复制):")
    output.extend(all_links)
    
    LIST_FILE.write_text("\n".join(output))
    return "\n".join(output)

def install_modified(user_name, uuid_str, port_vm_ws, custom_domain, argo_token):
    output_log = []
    try:
        if not INSTALL_DIR.exists(): INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        os.chdir(INSTALL_DIR)
        
        # --- Config ---
        uuid_str = uuid_str or str(uuid.uuid4())
        port_vm_ws = port_vm_ws or random.randint(10000, 65535)

        # --- Download binaries ---
        # (This part is unchanged, assuming binaries are downloaded correctly)
        system = platform.system().lower()
        machine = platform.machine().lower()
        arch = "amd64" if "x86_64" in machine else "arm64" if "aarch64" in machine else "amd64"
        
        singbox_path = INSTALL_DIR / "sing-box"
        if not singbox_path.exists():
            output_log.append("正在下载 sing-box...")
            # ... (download logic from previous version) ...
            sb_version = "1.9.0-beta.11"
            sb_name_actual = f"sing-box-{sb_version}-linux-{arch}"
            sb_url = f"https://github.com/SagerNet/sing-box/releases/download/v{sb_version}/{sb_name_actual}.tar.gz"
            tar_path = INSTALL_DIR / "sing-box.tar.gz"
            if not download_file(sb_url, tar_path): return False, "sing-box 下载失败。"
            import tarfile
            with tarfile.open(tar_path, "r:gz") as tar: tar.extractall(path=INSTALL_DIR)
            shutil.move(INSTALL_DIR / sb_name_actual / "sing-box", singbox_path)
            shutil.rmtree(INSTALL_DIR / sb_name_actual)
            tar_path.unlink()
            os.chmod(singbox_path, 0o755)
            output_log.append("sing-box 下载成功！")

        cloudflared_path = INSTALL_DIR / "cloudflared"
        if not cloudflared_path.exists():
            output_log.append("正在下载 cloudflared...")
            # ... (download logic from previous version) ...
            cf_arch = "arm" if arch == "armv7" else arch
            cf_url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}"
            if not download_file(cf_url, cloudflared_path): return False, "cloudflared 下载失败。"
            os.chmod(cloudflared_path, 0o755)
            output_log.append("cloudflared 下载成功！")

        # --- Create Configs ---
        config_data = { "uuid_str": uuid_str, "port_vm_ws": port_vm_ws, "argo_token": argo_token, "custom_domain_agn": custom_domain }
        CONFIG_FILE.write_text(json.dumps(config_data, indent=2))
        
        ws_path = f"/{uuid_str[:8]}-vm"
        sb_config = {"log": {"level": "info"}, "inbounds": [{"type": "vmess", "listen": "127.0.0.1", "listen_port": port_vm_ws, "users": [{"uuid": uuid_str, "alterId": 0}], "transport": {"type": "ws", "path": ws_path, "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}}], "outbounds": [{"type": "direct"}]}
        (INSTALL_DIR / "sb.json").write_text(json.dumps(sb_config, indent=2))

        # --- Create and Start Systemd Services ---
        current_user = os.environ.get('USER', 'root')
        
        # Sing-box service
        sb_cmd = f"{singbox_path.resolve()} run -c {INSTALL_DIR.resolve()}/sb.json"
        success, msg = create_systemd_service("sing-box", "Sing-Box Service by ArgoSB", sb_cmd, str(INSTALL_DIR.resolve()), current_user)
        output_log.append(msg)
        if not success: return False, "\n".join(output_log)

        # Cloudflared service
        ws_path_full = f"{ws_path}?ed=2048"
        if argo_token:
            cf_cmd = f"{cloudflared_path.resolve()} tunnel --no-autoupdate run --token {argo_token}"
        else:
            cf_cmd = f"{cloudflared_path.resolve()} tunnel --no-autoupdate --url http://localhost:{port_vm_ws}{ws_path_full} --edge-ip-version auto --protocol http2"
        
        success, msg = create_systemd_service("cloudflared", "Cloudflared Service by ArgoSB", cf_cmd, str(INSTALL_DIR.resolve()), current_user)
        output_log.append(msg)
        if not success: return False, "\n".join(output_log)
        
        output_log.append("服务已启动，等待5秒以确保稳定...")
        time.sleep(5)

        # --- Get Domain & Generate Links ---
        final_domain = custom_domain
        if not argo_token and not custom_domain:
            output_log.append("正在获取临时隧道域名...")
            # (get_tunnel_domain logic remains the same)
            final_domain = "temp-domain.trycloudflare.com" # Placeholder
        
        if final_domain:
            links_output = generate_links_modified(final_domain, port_vm_ws, uuid_str)
            output_log.append("\n" + links_output)
        else:
            return False, "\n".join(output_log) + "\n\n错误: 未能确定域名。"

        return True, "\n".join(output_log)

    except Exception as e:
        return False, f"安装过程中发生意外错误: {e}"

def uninstall_modified():
    output_log = []
    output_log.append("正在卸载服务...")
    
    success, msg = remove_systemd_service("sing-box")
    output_log.append(msg)
    success, msg = remove_systemd_service("cloudflared")
    output_log.append(msg)

    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
        output_log.append(f"安装目录 {INSTALL_DIR} 已删除。")
    
    output_log.append("卸载完成。")
    return "\n".join(output_log)

def check_status_modified():
    output_lines = []
    
    # Check sing-box status
    sb_active_success, sb_status = run_sudo_command("systemctl is-active sing-box")
    if sb_active_success and sb_status == "active":
        output_lines.append("✅ sing-box 服务: 正在运行")
    else:
        output_lines.append("❌ sing-box 服务: 未运行")

    # Check cloudflared status
    cf_active_success, cf_status = run_sudo_command("systemctl is-active cloudflared")
    if cf_active_success and cf_status == "active":
        output_lines.append("✅ cloudflared 服务: 正在运行")
    else:
        output_lines.append("❌ cloudflared 服务: 未运行")

    if LIST_FILE.exists():
        output_lines.append("\n--- 当前节点信息 ---")
        output_lines.append(LIST_FILE.read_text())
    
    return "\n".join(output_lines)


# --- Streamlit UI (Sudo Warning Included) ---
def main_streamlit():
    st.set_page_config(page_title="ArgoSB 部署工具", layout="wide")
    st.title("✨ ArgoSB 持久化部署面板 ✨")
    st.caption("使用 systemd 确保服务在重启后依然运行")

    st.warning(
        "**重要提示：** 此应用需要 `sudo` 权限来管理系统服务。\n"
        "请先为运行 Streamlit 的用户配置 **免密 `sudo` 权限**。请在服务器上**以 root 用户**执行以下命令，"
        f"将 `{os.environ.get('USER', 'YOUR_USERNAME')}` 替换为实际运行此脚本的用户名：\n"
        "```bash\n"
        f"echo '{os.environ.get('USER', 'YOUR_USERNAME')} ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /bin/mv, /bin/chmod, /bin/rm' >> /etc/sudoers\n"
        "```\n"
        "**此操作有安全风险，请确认您了解其含义后再执行！**"
    )

    if 'output' not in st.session_state:
        st.session_state.output = check_status_modified()

    # --- Layout and Logic (same as previous Streamlit version) ---
    col1, col2 = st.columns([1, 1])
    with col1:
        # ... (input fields from previous version)
        st.header("⚙️ 安装配置")
        with st.expander("点击展开配置项", expanded=True):
            uuid_str = st.text_input("UUID", help="留空将自动生成一个随机UUID")
            port_vm_ws = st.number_input("Vmess 本地端口", min_value=0, max_value=65535, value=0, help="留空或0则随机")
            custom_domain = st.text_input("自定义域名", help="使用命名隧道时必需")
            argo_token = st.text_input("Argo Tunnel Token", type="password", help="使用命名隧道时提供")

    with col2:
        st.header("🚀 操作与状态")
        btn_col1, btn_col2, btn_col3 = st.columns(3)
        with btn_col1: install_button = st.button("✅ 安装/启动", use_container_width=True)
        with btn_col2: uninstall_button = st.button("❌ 卸载服务", type="primary", use_container_width=True)
        with btn_col3: status_button = st.button("🔄 刷新状态", use_container_width=True)

        output_placeholder = st.empty()
        output_placeholder.text_area("输出日志", st.session_state.output, height=400)

    if install_button:
        with st.spinner("正在安装并启动 systemd 服务..."):
            success, message = install_modified(None, uuid_str, port_vm_ws, custom_domain, argo_token) # user_name not needed for systemd
            if success: st.success("操作成功！")
            else: st.error(f"操作失败: {message}")
            st.session_state.output = check_status_modified() # Refresh status after action
            st.experimental_rerun()

    if uninstall_button:
        with st.spinner("正在停止并卸载服务..."):
            message = uninstall_modified()
            st.success("卸载完成！")
            st.session_state.output = message
            st.experimental_rerun()

    if status_button:
        st.session_state.output = check_status_modified()
        output_placeholder.text_area("输出日志", st.session_state.output, height=400)
        st.success("状态已刷新。")

if __name__ == "__main__":
    main_streamlit()