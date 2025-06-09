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
import streamlit as st

# --- 全局配置 ---
INSTALL_DIR = Path.home() / ".agsb"
CONFIG_FILE = INSTALL_DIR / "config.json"
SECRETS_FILE = INSTALL_DIR / "secrets.json" # 新增: 存储密码的文件
SB_PID_FILE = INSTALL_DIR / "sbpid.log"
ARGO_PID_FILE = INSTALL_DIR / "sbargopid.log"
LIST_FILE = INSTALL_DIR / "list.txt"
LOG_FILE = INSTALL_DIR / "argo.log"
SB_LOG_FILE = INSTALL_DIR / "sb.log"
CUSTOM_DOMAIN_FILE = INSTALL_DIR / "custom_domain.txt"
ALL_NODES_FILE = INSTALL_DIR / "allnodes.txt" # 新增: 方便读取所有节点

# 密码将从 SECRETS_FILE 加载
SECRET_KEY = None
NODE_VIEW_PASSWORD = None

# --- 辅助函数 (保持不变) ---
def http_get(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read().decode('utf-8')
    except Exception:
        return None

def download_file(url, target_path, mode='wb'):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(target_path, mode) as out_file:
            shutil.copyfileobj(response, out_file)
        return True
    except Exception:
        return False

def generate_vmess_link(config):
    vmess_obj = {
        "v": "2", "ps": config.get("ps", "ArgoSB-TLS"), "add": config.get("add", ""),
        "port": str(config.get("port", "443")), "id": config.get("id", ""), "aid": "0",
        "scy": "auto", "net": "ws", "type": "none", "host": config.get("host", ""),
        "path": config.get("path", ""), "tls": "tls", "sni": config.get("sni", "")
    }
    vmess_str = json.dumps(vmess_obj, separators=(',', ':'))
    return f"vmess://{base64.b64encode(vmess_str.encode('utf-8')).decode('utf-8').rstrip('=')}"

def get_tunnel_domain():
    for _ in range(15):
        if LOG_FILE.exists():
            try:
                log_content = LOG_FILE.read_text()
                match = re.search(r'https://([a-zA-Z0-9.-]+\.trycloudflare\.com)', log_content)
                if match: return match.group(1)
            except Exception: pass
        time.sleep(2)
    return None

# --- 核心逻辑函数 (大部分保持不变) ---
def generate_links_modified(domain, port_vm_ws, uuid_str):
    output = []
    ws_path = f"/{uuid_str[:8]}-vm"
    hostname = socket.gethostname()[:10]
    all_links = []
    cf_ips_tls = {"104.16.0.0": "443", "104.17.0.0": "8443", "104.18.0.0": "2053", "104.19.0.0": "2083", "104.20.0.0": "2087"}
    for ip, port in cf_ips_tls.items():
        all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-{hostname}-{ip.split('.')[2]}-{port}", "add": ip, "port": port, "id": uuid_str, "host": domain, "path": ws_path, "sni": domain}))
    all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-Direct-{hostname}", "add": domain, "port": "443", "id": uuid_str, "host": domain, "path": ws_path, "sni": domain}))

    ALL_NODES_FILE.write_text("\n".join(all_links) + "\n")
    CUSTOM_DOMAIN_FILE.write_text(domain)

    output.append("✅ **服务启动成功! (仅TLS节点)**\n---\n")
    output.append(f"**域名 (Domain):** `{domain}`\n**UUID:** `{uuid_str}`\n**本地Vmess端口:** `{port_vm_ws}`\n**WebSocket路径:** `{ws_path}`\n---\n")
    output.append("**所有节点链接 (可直接复制):**")
    output.extend(all_links)

    list_content_for_file = [re.sub(r'[`*]', '', line) for line in output]
    LIST_FILE.write_text("\n".join(list_content_for_file))
    return "\n".join(output)

def _start_services():
    # ... (此函数无变化)
    if not CONFIG_FILE.exists(): return
    config = json.loads(CONFIG_FILE.read_text())
    uuid_str, port_vm_ws, argo_token = config["uuid_str"], config["port_vm_ws"], config.get("argo_token")
    singbox_path = INSTALL_DIR / "sing-box"
    cloudflared_path = INSTALL_DIR / "cloudflared"
    sb_cmd = [str(singbox_path), 'run', '-c', 'sb.json']
    with open(SB_LOG_FILE, "w") as sb_log:
        sb_process = subprocess.Popen(sb_cmd, cwd=INSTALL_DIR, stdout=sb_log, stderr=subprocess.STDOUT)
    SB_PID_FILE.write_text(str(sb_process.pid))
    if argo_token:
        cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate', 'run', '--token', argo_token]
    else:
        cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate', '--url', f'http://localhost:{port_vm_ws}', '--edge-ip-version', 'auto', '--protocol', 'http2']
    with open(LOG_FILE, "w") as cf_log:
        cf_process = subprocess.Popen(cf_cmd, cwd=INSTALL_DIR, stdout=cf_log, stderr=subprocess.STDOUT)
    ARGO_PID_FILE.write_text(str(cf_process.pid))

def install_or_start_modified(uuid_str_in, port_vm_ws_in, custom_domain_in, argo_token_in):
    # ... (此函数无变化)
    try:
        if not INSTALL_DIR.exists(): INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        if CONFIG_FILE.exists():
            config = json.loads(CONFIG_FILE.read_text())
        else:
            config = {"uuid_str": uuid_str_in or str(uuid.uuid4()), "port_vm_ws": port_vm_ws_in or random.randint(10000, 65535), "custom_domain_agn": custom_domain_in, "argo_token": argo_token_in}
            CONFIG_FILE.write_text(json.dumps(config, indent=2))
        uuid_str, port_vm_ws, custom_domain, argo_token = config["uuid_str"], config["port_vm_ws"], config.get("custom_domain_agn"), config.get("argo_token")
        arch = "amd64" if "x86_64" in platform.machine().lower() else "arm64" if "aarch64" in platform.machine().lower() else "amd64"
        singbox_path = INSTALL_DIR / "sing-box"
        if not singbox_path.exists():
            sb_version, sb_name_actual = "1.9.0-beta.11", f"sing-box-1.9.0-beta.11-linux-{arch}"
            tar_path = INSTALL_DIR / "sing-box.tar.gz"
            if not download_file(f"https://github.com/SagerNet/sing-box/releases/download/v{sb_version}/{sb_name_actual}.tar.gz", tar_path): return False, "sing-box 下载失败。"
            import tarfile
            with tarfile.open(tar_path, "r:gz") as tar: tar.extractall(path=INSTALL_DIR)
            shutil.move(INSTALL_DIR / sb_name_actual / "sing-box", singbox_path)
            shutil.rmtree(INSTALL_DIR / sb_name_actual)
            tar_path.unlink()
            os.chmod(singbox_path, 0o755)
        cloudflared_path = INSTALL_DIR / "cloudflared"
        if not cloudflared_path.exists():
            cf_arch = "amd64" if arch == "amd64" else "arm"
            if not download_file(f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}", cloudflared_path): return False, "cloudflared 下载失败。"
            os.chmod(cloudflared_path, 0o755)
        ws_path = f"/{uuid_str[:8]}-vm"
        sb_config = {"log": {"level": "info"}, "inbounds": [{"type": "vmess", "listen": "127.0.0.1", "listen_port": port_vm_ws, "users": [{"uuid": uuid_str, "alterId": 0}], "transport": {"type": "ws", "path": ws_path}}], "outbounds": [{"type": "direct"}]}
        (INSTALL_DIR / "sb.json").write_text(json.dumps(sb_config, indent=2))
        _start_services()
        time.sleep(5)
        final_domain = custom_domain or (get_tunnel_domain() if not argo_token else None)
        if not final_domain:
            return False, "未能确定域名。请检查 cloudflared 日志 (`.agsb/argo.log`)。"
        return True, generate_links_modified(final_domain, port_vm_ws, uuid_str)
    except Exception as e:
        return False, f"安装过程中发生意外错误: {e}"

def _stop_services():
    # ... (此函数无变化)
    for pid_file in [SB_PID_FILE, ARGO_PID_FILE]:
        if pid_file.exists():
            try:
                pid = pid_file.read_text().strip()
                if pid:
                    try: os.kill(int(pid), 9)
                    except ProcessLookupError: pass
                pid_file.unlink()
            except Exception: pass
    subprocess.run("pkill -9 -f 'sing-box run'", shell=True, capture_output=True)
    subprocess.run("pkill -9 -f 'cloudflared tunnel'", shell=True, capture_output=True)

def uninstall_modified():
    # ... (此函数无变化)
    _stop_services()
    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
    return "✅ 卸载完成。所有配置和进程已清除。请刷新页面以重新配置。"

def check_status_modified():
    # ... (此函数无变化)
    if not CONFIG_FILE.exists(): return "服务未安装。"
    try:
        sb_pid = SB_PID_FILE.read_text().strip() if SB_PID_FILE.exists() else None
        cf_pid = ARGO_PID_FILE.read_text().strip() if ARGO_PID_FILE.exists() else None
        sb_running = sb_pid and subprocess.run(f"ps -p {sb_pid}", shell=True, capture_output=True).returncode == 0
        cf_running = cf_pid and subprocess.run(f"ps -p {cf_pid}", shell=True, capture_output=True).returncode == 0
        if sb_running and cf_running:
            return f"✅ **服务正在运行中**\n\n---\n" + (LIST_FILE.read_text() if LIST_FILE.exists() else "节点信息文件丢失，请重启服务。")
        else:
            status = ["❌ **服务状态异常**", "  - sing-box 正常" if sb_running else "  - sing-box 未运行", "  - cloudflared 正常" if cf_running else "  - cloudflared 未运行"]
            return "\n".join(status)
    except Exception:
        return "检查状态时出错。"

def health_check_and_heal():
    # ... (此函数无变化)
    if not CONFIG_FILE.exists(): return "服务未安装，跳过健康检查。"
    messages = []
    try:
        sb_pid = SB_PID_FILE.read_text().strip() if SB_PID_FILE.exists() else None
        if not sb_pid or subprocess.run(f"ps -p {sb_pid}", shell=True, capture_output=True).returncode != 0:
            messages.append("⚠️ 检测到 sing-box 进程停止，正在尝试重启...")
            sb_cmd = [str(INSTALL_DIR / "sing-box"), 'run', '-c', 'sb.json']
            with open(SB_LOG_FILE, "a") as sb_log:
                sb_process = subprocess.Popen(sb_cmd, cwd=INSTALL_DIR, stdout=sb_log, stderr=subprocess.STDOUT)
            SB_PID_FILE.write_text(str(sb_process.pid))
            messages.append("✅ 已发送 sing-box 重启指令。")
        cf_pid = ARGO_PID_FILE.read_text().strip() if ARGO_PID_FILE.exists() else None
        if not cf_pid or subprocess.run(f"ps -p {cf_pid}", shell=True, capture_output=True).returncode != 0:
            messages.append("⚠️ 检测到 cloudflared 进程停止，正在尝试重启...")
            config = json.loads(CONFIG_FILE.read_text())
            port_vm_ws, argo_token = config["port_vm_ws"], config.get("argo_token")
            if argo_token:
                cf_cmd = [str(INSTALL_DIR / "cloudflared"), 'tunnel', '--no-autoupdate', 'run', '--token', argo_token]
            else:
                cf_cmd = [str(INSTALL_DIR / "cloudflared"), 'tunnel', '--no-autoupdate', '--url', f'http://localhost:{port_vm_ws}', '--edge-ip-version', 'auto', '--protocol', 'http2']
            with open(LOG_FILE, "a") as cf_log:
                cf_process = subprocess.Popen(cf_cmd, cwd=INSTALL_DIR, stdout=cf_log, stderr=subprocess.STDOUT)
            ARGO_PID_FILE.write_text(str(cf_process.pid))
            messages.append("✅ 已发送 cloudflared 重启指令。")
    except Exception as e:
        messages.append(f"自愈检查时发生错误: {e}")
    return "\n".join(messages) if messages else f"✅ 健康检查通过，所有服务均在运行。({datetime.now().strftime('%H:%M:%S')})"

# --- UI 渲染函数 (已重构) ---

### 新增 ###: 首次运行的密码设置页面
def render_password_setup_ui():
    st.set_page_config(page_title="首次设置", layout="centered")
    st.title("🔐 首次运行 - 请设置密码")
    st.info("您需要设置一个主访问密码和一个节点查看密码。请务必牢记！")

    with st.form("password_setup_form"):
        secret_key_in = st.text_input("设置主访问密码 (用于进入管理页面)", type="password")
        secret_key_confirm = st.text_input("确认主访问密码", type="password")
        st.markdown("---")
        node_password_in = st.text_input("设置节点查看密码 (用于解密节点信息)", type="password")
        node_password_confirm = st.text_input("确认节点查看密码", type="password")
        submitted = st.form_submit_button("保存密码并继续")

        if submitted:
            if not secret_key_in or not node_password_in:
                st.error("所有密码字段都不能为空！")
            elif secret_key_in != secret_key_confirm:
                st.error("两次输入的主访问密码不匹配！")
            elif node_password_in != node_password_confirm:
                st.error("两次输入的节点查看密码不匹配！")
            else:
                secrets = {
                    "secret_key": secret_key_in,
                    "node_view_password": node_password_in
                }
                if not INSTALL_DIR.exists():
                    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
                SECRETS_FILE.write_text(json.dumps(secrets, indent=2))
                st.success("密码已保存！页面将自动刷新...")
                time.sleep(2)
                st.rerun()

def render_real_ui():
    # ... (此函数无大变化)
    st.set_page_config(page_title="部署工具", layout="wide")
    st.header("⚙️ 服务配置与管理")
    if 'output' in st.session_state and st.session_state.output:
        st.code(st.session_state.output)
        st.session_state.output = ""
    with st.spinner("正在执行健康检查..."):
        heal_message = health_check_and_heal()
    st.info(heal_message)
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("控制面板")
        uuid_str_in, port_vm_ws_in, custom_domain_in, argo_token_in = "", 0, "", ""
        submitted = False
        if not CONFIG_FILE.exists():
            with st.form("config_form"):
                st.write("首次安装，请输入配置：")
                uuid_str_in = st.text_input("UUID", help="强烈建议留空，程序会自动生成并固定保存")
                port_vm_ws_in = st.number_input("Vmess 本地端口", min_value=0, max_value=65535, value=0, help="留空或0则随机生成并固定保存")
                st.markdown("---")
                st.write("如需使用Cloudflare Zero Trust隧道，请填写：")
                custom_domain_in = st.text_input("你的域名 (例如 my.domain.com)")
                argo_token_in = st.text_input("Argo Tunnel Token", type="password")
                submitted = st.form_submit_button("保存并启动")
        else:
            st.success("已检测到固定配置。")
            if st.button("🔄 重启服务", use_container_width=True):
                with st.spinner("正在重启服务..."):
                    _stop_services()
                    time.sleep(2)
                    _start_services()
                    st.session_state.output = "✅ 服务重启指令已发送。"
                st.rerun()
            if st.button("卸载所有服务和配置", type="primary", use_container_width=True):
                 with st.spinner("正在卸载..."):
                    st.session_state.output = uninstall_modified()
                 st.rerun()
    if submitted:
        with st.spinner("正在执行安装/启动流程..."):
            success, message = install_or_start_modified(uuid_str_in, port_vm_ws_in, custom_domain_in, argo_token_in)
            if not success:
                st.error(message)
            st.session_state.output = message
            st.rerun()
    with col2:
        st.subheader("节点信息")
        st.warning("节点信息包含敏感数据，已被加密隐藏。")
        with st.expander("🔑 解密并查看节点信息"):
            password = st.text_input("请输入节点查看密码", type="password", key="node_password_input")
            if st.button("确认", key="submit_node_password"):
                if password == NODE_VIEW_PASSWORD:
                    st.session_state.node_info_unlocked = True
                    st.rerun()
                else:
                    st.error("密码错误！")

def render_node_info_page():
    ### 修改 ###: 增加一键复制功能
    st.set_page_config(page_title="节点信息", layout="wide")
    st.title("🚀 节点信息详情")
    st.info("请及时复制所需信息。离开此页面后将需要重新验证。")
    node_info = check_status_modified()
    st.markdown(node_info, unsafe_allow_html=True)
    st.markdown("---")
    
    # 一键复制区域
    if ALL_NODES_FILE.exists():
        st.subheader("📋 一键复制所有节点链接")
        all_nodes_content = ALL_NODES_FILE.read_text()
        st.code(all_nodes_content, language="text")
    
    if st.button("返回并锁定 🔐", type="primary"):
        st.session_state.node_info_unlocked = False
        st.rerun()

def render_fake_ui():
    ### 修改 ###: 移除密码提示
    st.set_page_config(page_title="天气查询", layout="centered")
    st.title("🌦️ 实时天气查询")
    st.write("一个简单的天气查询工具。由于API限制，可能偶尔查询失败。")
    city = st.text_input("请输入城市名或秘密口令：", "Beijing")
    if st.button("查询天气"):
        if city == SECRET_KEY:
            st.session_state.authenticated = True
            st.rerun()
        else:
            with st.spinner(f"正在查询 {city} 的天气..."):
                time.sleep(2)
                messages = [f"抱歉，查询 **{city}** 的天气失败。错误代码：503。", f"API密钥已过期，无法查询 **{city}**。", f"网络超时，无法获取 **{city}** 的数据。"]
                st.error(random.choice(messages))
    st.markdown("---")
    st.info("这是一个开源项目，旨在演示Streamlit的数据可视化能力。")

def main():
    # 初始化 session_state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'node_info_unlocked' not in st.session_state:
        st.session_state.node_info_unlocked = False
    if 'output' not in st.session_state:
        st.session_state.output = ""

    ### 修改 ###: 密码加载与首次设置逻辑
    global SECRET_KEY, NODE_VIEW_PASSWORD
    if not SECRETS_FILE.exists():
        render_password_setup_ui()
        return # 停止执行后续代码，直到密码设置完成

    try:
        secrets = json.loads(SECRETS_FILE.read_text())
        SECRET_KEY = secrets.get("secret_key")
        NODE_VIEW_PASSWORD = secrets.get("node_view_password")
        if not SECRET_KEY or not NODE_VIEW_PASSWORD:
            st.error("密码文件损坏或不完整，请删除 `.agsb/secrets.json` 文件后刷新页面重置。")
            return
    except Exception as e:
        st.error(f"加载密码文件失败: {e}。请删除 `.agsb/secrets.json` 文件后刷新页面重置。")
        return

    # 主 UI 逻辑
    if st.session_state.authenticated:
        if st.session_state.node_info_unlocked:
            render_node_info_page()
        else:
            render_real_ui()
    else:
        render_fake_ui()

if __name__ == "__main__":
    main()
