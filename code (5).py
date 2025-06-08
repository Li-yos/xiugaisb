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
SB_PID_FILE = INSTALL_DIR / "sbpid.log"
ARGO_PID_FILE = INSTALL_DIR / "sbargopid.log"
LIST_FILE = INSTALL_DIR / "list.txt"
LOG_FILE = INSTALL_DIR / "argo.log"
CUSTOM_DOMAIN_FILE = INSTALL_DIR / "custom_domain.txt"
SECRET_KEY = "ljt123"  # 你可以修改成任何你喜欢的秘密口令

# --- 辅助函数 (与之前版本相同) ---
def http_get(url, timeout=10):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as response:
            return response.read().decode('utf-8')
    except Exception: return None

def download_file(url, target_path, mode='wb'):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx) as response, open(target_path, mode) as out_file:
            shutil.copyfileobj(response, out_file)
        return True
    except Exception: return False

def generate_vmess_link(config):
    vmess_obj = {"v": "2", "ps": config.get("ps", "ArgoSB-TLS"), "add": config.get("add", ""),"port": str(config.get("port", "443")), "id": config.get("id", ""), "aid": "0","net": "ws", "type": "none", "host": config.get("host", ""), "path": config.get("path", ""),"tls": "tls", "sni": config.get("sni", "")}
    vmess_str = json.dumps(vmess_obj, sort_keys=True)
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


# --- 核心逻辑函数 (与之前版本相同) ---
def generate_links_modified(domain, port_vm_ws, uuid_str):
    output = []
    ws_path = f"/{uuid_str[:8]}-vm"
    ws_path_full = f"{ws_path}?ed=2048"
    hostname = socket.gethostname()[:10]
    all_links = []
    cf_ips_tls = {"104.16.0.0": "443", "104.17.0.0": "8443", "104.18.0.0": "2053", "104.19.0.0": "2083", "104.20.0.0": "2087"}
    for ip, port in cf_ips_tls.items():
        all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-{hostname}-{ip.split('.')[2]}-{port}", "add": ip, "port": port, "id": uuid_str, "host": domain, "path": ws_path_full, "sni": domain}))
    all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-Direct-{hostname}", "add": domain, "port": "443", "id": uuid_str, "host": domain, "path": ws_path_full, "sni": domain}))
    (INSTALL_DIR / "allnodes.txt").write_text("\n".join(all_links) + "\n")
    CUSTOM_DOMAIN_FILE.write_text(domain)
    output.append("✅ **服务启动成功! (仅TLS节点)**\n---\n")
    output.append(f"**域名 (Domain):** `{domain}`\n**UUID:** `{uuid_str}`\n**本地Vmess端口:** `{port_vm_ws}`\n**WebSocket路径:** `{ws_path_full}`\n---\n")
    output.append("**所有节点链接 (可直接复制):**")
    output.extend(all_links)
    list_content_for_file = [re.sub(r'[`*]', '', line) for line in output]
    LIST_FILE.write_text("\n".join(list_content_for_file))
    return "\n".join(output)

def install_or_start_modified(uuid_str_in, port_vm_ws_in, custom_domain_in, argo_token_in):
    try:
        if not INSTALL_DIR.exists(): INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        os.chdir(INSTALL_DIR)
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
            cf_arch = "arm" if arch == "armv7" else arch
            if not download_file(f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}", cloudflared_path): return False, "cloudflared 下载失败。"
            os.chmod(cloudflared_path, 0o755)

        ws_path = f"/{uuid_str[:8]}-vm"
        (INSTALL_DIR / "sb.json").write_text(json.dumps({"log": {"level": "info"}, "inbounds": [{"type": "vmess", "listen": "127.0.0.1", "listen_port": port_vm_ws, "users": [{"uuid": uuid_str, "alterId": 0}], "transport": {"type": "ws", "path": ws_path, "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}}], "outbounds": [{"type": "direct"}]}))
        (INSTALL_DIR / "start_sb.sh").write_text(f'#!/bin/bash\ncd {INSTALL_DIR.resolve()}\n./sing-box run -c sb.json > sb.log 2>&1 &\necho $! > {SB_PID_FILE.name}\n')
        os.chmod(INSTALL_DIR / "start_sb.sh", 0o755)
        
        ws_path_full = f"{ws_path}?ed=2048"
        cf_cmd = f"./cloudflared tunnel --no-autoupdate run --token {argo_token}" if argo_token else f"./cloudflared tunnel --no-autoupdate --url http://localhost:{port_vm_ws}{ws_path_full} --edge-ip-version auto --protocol http2"
        (INSTALL_DIR / "start_cf.sh").write_text(f'#!/bin/bash\ncd {INSTALL_DIR.resolve()}\n{cf_cmd} > {LOG_FILE.name} 2>&1 &\necho $! > {ARGO_PID_FILE.name}\n')
        os.chmod(INSTALL_DIR / "start_cf.sh", 0o755)
        
        subprocess.run(str(INSTALL_DIR / "start_sb.sh"), shell=True)
        subprocess.run(str(INSTALL_DIR / "start_cf.sh"), shell=True)
        time.sleep(5)
        
        final_domain = custom_domain or (get_tunnel_domain() if not argo_token else None)
        if not final_domain: return False, "未能确定域名。"
        
        return True, generate_links_modified(final_domain, port_vm_ws, uuid_str)
    except Exception as e:
        return False, f"安装过程中发生意外错误: {e}"

def uninstall_modified():
    for pid_file in [SB_PID_FILE, ARGO_PID_FILE]:
        if pid_file.exists():
            try:
                pid = pid_file.read_text().strip()
                if pid: subprocess.run(f"kill -9 {pid}", shell=True, capture_output=True)
            except Exception: pass
    subprocess.run("pkill -9 -f 'sing-box run'", shell=True)
    subprocess.run("pkill -9 -f 'cloudflared tunnel'", shell=True)
    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
    return "卸载完成。所有配置和进程已清除。请刷新页面以重新配置。"

def check_status_modified():
    if not CONFIG_FILE.exists(): return "服务未安装。"
    try:
        sb_pid = SB_PID_FILE.read_text().strip() if SB_PID_FILE.exists() else None
        cf_pid = ARGO_PID_FILE.read_text().strip() if ARGO_PID_FILE.exists() else None
        sb_running = sb_pid and subprocess.run(f"ps -p {sb_pid}", shell=True, capture_output=True).returncode == 0
        cf_running = cf_pid and subprocess.run(f"ps -p {cf_pid}", shell=True, capture_output=True).returncode == 0
        if sb_running and cf_running:
            return f"✅ **服务正在运行中**\n\n---\n" + (LIST_FILE.read_text() if LIST_FILE.exists() else "节点信息文件丢失，请重启服务。")
        else:
            status = ["❌ **服务状态异常**", "  - sing-box 未运行" if not sb_running else "  - cloudflared 未运行" if not cf_running else ""]
            return "\n".join(filter(None, status))
    except Exception: return "检查状态时出错。"


# --- UI 渲染函数 ---

def render_real_ui():
    """渲染真正的 ArgoSB 部署面板"""
    st.header("⚙️ 服务配置 (隐私模式)")
    st.info("首次运行时，请填写配置。之后将自动使用已保存的配置。如需修改，请先卸载。")
    
    if 'output' not in st.session_state:
        st.session_state.output = check_status_modified()

    col1, col2 = st.columns([1, 1.2])

    with col1:
        # 定义表单和输入变量
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
                    success, message = install_or_start_modified(None, None, None, None)
                    st.session_state.output = message
                st.experimental_rerun()

            if st.button("卸载所有服务和配置", type="primary", use_container_width=True):
                 with st.spinner("正在卸载..."):
                    st.session_state.output = uninstall_modified()
                 st.experimental_rerun()

    # 将表单提交后的处理逻辑移到所有UI元素定义之后
    if submitted:
        with st.spinner("正在执行安装/启动流程..."):
            success, message = install_or_start_modified(uuid_str_in, port_vm_ws_in, custom_domain_in, argo_token_in)
            st.session_state.output = message
        # 表单提交后，Streamlit会自动rerun，这里不需要手动调用

    with col2:
        st.header("🚀 状态与节点信息")
        if st.button("🔄 刷新当前状态"):
            st.session_state.output = check_status_modified()
            # 这里可以加一个rerun，以确保点击后立即看到刷新结果
            st.experimental_rerun()
        
        st.markdown(st.session_state.output, unsafe_allow_html=True)


def render_fake_ui():
    """渲染伪装的天气应用界面"""
    st.title("🌦️ 实时天气查询")
    st.write("一个简单的天气查询工具。由于API限制，可能偶尔查询失败。")
    city = st.text_input("请输入城市名或秘密口令：", "Beijing")
    if st.button("查询天气"):
        if city == SECRET_KEY:
            st.session_state.authenticated = True
            st.experimental_rerun()
        else:
            with st.spinner(f"正在查询 {city} 的天气..."):
                time.sleep(2)
                messages = [f"抱歉，查询 **{city}** 的天气失败。错误代码：503。", f"API密钥已过期，无法查询 **{city}**。", f"网络超时，无法获取 **{city}** 的数据。"]
                st.error(random.choice(messages))
    st.markdown("---")
    st.info("这是一个开源项目，旨在演示Streamlit的数据可视化能力。")

# --- 主程序入口 ---
def main():
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

    if st.session_state.authenticated:
        st.set_page_config(page_title="部署工具", layout="wide")
        render_real_ui()
    else:
        st.set_page_config(page_title="天气查询", layout="centered")
        render_fake_ui()

if __name__ == "__main__":
    main()