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
SECRETS_FILE = INSTALL_DIR / "secrets.json"
SB_PID_FILE = INSTALL_DIR / "sbpid.log"
ARGO_PID_FILE = INSTALL_DIR / "sbargopid.log"
LIST_FILE = INSTALL_DIR / "list.txt"
LOG_FILE = INSTALL_DIR / "argo.log"
SB_LOG_FILE = INSTALL_DIR / "sb.log"
CUSTOM_DOMAIN_FILE = INSTALL_DIR / "custom_domain.txt"
ALL_NODES_FILE = INSTALL_DIR / "allnodes.txt"
SINGBOX_CONFIG_FILE = INSTALL_DIR / "singbox_client_config.json"

SECRET_KEY = None
NODE_VIEW_PASSWORD = None

# --- 辅助函数 ---
def http_get(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read().decode('utf-8')
    except Exception: return None

def download_file(url, target_path, mode='wb'):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(target_path, mode) as out_file:
            shutil.copyfileobj(response, out_file)
        return True
    except Exception: return False

def generate_vmess_link(config):
    # 路径固定为根路径
    vmess_obj = {"v": "2", "ps": config.get("ps"), "add": config.get("add"), "port": str(config.get("port")), "id": config.get("id"), "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": config.get("host"), "path": "/", "tls": "tls", "sni": config.get("sni")}
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

# --- 核心配置生成逻辑 ---

def generate_singbox_config(domain, uuid_str):
    ws_path = "/"
    hostname = socket.gethostname()[:10]
    outbounds, node_tags = [], []

    cf_ips_tls = {"104.16.0.0": "443", "104.17.0.0": "8443", "104.18.0.0": "2053", "104.19.0.0": "2083", "104.20.0.0": "2087"}
    for ip, port in cf_ips_tls.items():
        node_name = f"VMWS-TLS-{hostname}-{ip.split('.')[2]}-{port}"
        node_tags.append(node_name)
        outbounds.append({"type": "vmess", "tag": node_name, "server": ip, "server_port": int(port), "uuid": uuid_str, "security": "auto", "alter_id": 0, "transport": {"type": "ws", "path": ws_path, "headers": {"Host": domain}}, "tls": {"enabled": True, "server_name": domain, "insecure": False}})

    direct_node_name = f"VMWS-TLS-Direct-{hostname}"
    node_tags.append(direct_node_name)
    outbounds.append({"type": "vmess", "tag": direct_node_name, "server": domain, "server_port": 443, "uuid": uuid_str, "security": "auto", "alter_id": 0, "transport": {"type": "ws", "path": ws_path, "headers": {"Host": domain}}, "tls": {"enabled": True, "server_name": domain, "insecure": False}})

    outbounds.insert(0, {"type": "selector", "tag": "节点选择", "outbounds": node_tags, "default": direct_node_name})
    outbounds.extend([{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}])

    random_socks_port = random.randint(2000, 50000)
    random_http_port = random_socks_port + 1
    config = {"log": {"level": "info", "timestamp": True}, "dns": {"servers": [{"address": "8.8.8.8"}, {"address": "1.1.1.1"}]}, "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": "tun0", "inet4_address": "172.19.0.1/30", "auto_route": True, "strict_route": True}, {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": random_socks_port}, {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": random_http_port}], "outbounds": outbounds, "route": {"rules": [{"protocol": "dns", "outbound": "direct"}], "final": "节点选择"}}
    return json.dumps(config, indent=2)

def generate_links_modified(domain, port_vm_ws, uuid_str):
    hostname = socket.gethostname()[:10]
    all_links = []
    cf_ips_tls = {"104.16.0.0": "443", "104.17.0.0": "8443", "104.18.0.0": "2053", "104.19.0.0": "2083", "104.20.0.0": "2087"}
    for ip, port in cf_ips_tls.items():
        all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-{hostname}-{ip.split('.')[2]}-{port}", "add": ip, "port": port, "id": uuid_str, "host": domain, "sni": domain}))
    all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-Direct-{hostname}", "add": domain, "port": "443", "id": uuid_str, "host": domain, "sni": domain}))

    ALL_NODES_FILE.write_text("\n".join(all_links) + "\n")
    output = ["✅ **服务启动成功!**\n---\n", f"**域名 (Domain):** `{domain}`\n**UUID:** `{uuid_str}`\n**本地端口:** `{port_vm_ws}`\n**WebSocket路径:** `/`\n---\n", "**Vmess 链接 (可复制):**"] + all_links
    list_content_for_file = [re.sub(r'[`*]', '', line) for line in output]
    LIST_FILE.write_text("\n".join(list_content_for_file))
    return "\n".join(output)

# --- 核心安装与进程管理 ---

def install_or_start_modified(uuid_str_in, port_vm_ws_in, custom_domain_in, argo_token_in):
    try:
        if not INSTALL_DIR.exists(): INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        config = json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {"uuid_str": uuid_str_in or str(uuid.uuid4()), "port_vm_ws": port_vm_ws_in or random.randint(10000, 65535), "custom_domain_agn": custom_domain_in, "argo_token": argo_token_in}
        if not CONFIG_FILE.exists(): CONFIG_FILE.write_text(json.dumps(config, indent=2))
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
            shutil.rmtree(INSTALL_DIR / sb_name_actual); tar_path.unlink(); os.chmod(singbox_path, 0o755)

        cloudflared_path = INSTALL_DIR / "cloudflared"
        if not cloudflared_path.exists():
            cf_arch = "amd64" if arch == "amd64" else "arm"
            if not download_file(f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}", cloudflared_path): return False, "cloudflared 下载失败。"
            os.chmod(cloudflared_path, 0o755)

        ### 核心修复: 简化服务器端 sb.json 配置, 增加 sniff ###
        sb_config = {"log": {"level": "info"}, "inbounds": [{"type": "vmess", "tag": "vmess-in", "listen": "127.0.0.1", "listen_port": port_vm_ws, "sniff": True, "users": [{"uuid": uuid_str, "alterId": 0}], "transport": {"type": "ws", "path": "/"}}], "outbounds": [{"type": "direct"}]}
        (INSTALL_DIR / "sb.json").write_text(json.dumps(sb_config, indent=2))
        
        _start_services()
        time.sleep(5)
        
        final_domain = custom_domain or (get_tunnel_domain() if not argo_token else None)
        if not final_domain: return False, "未能确定域名。请检查 cloudflared 日志 (`.agsb/argo.log`)。"

        links_output = generate_links_modified(final_domain, port_vm_ws, uuid_str)
        singbox_config_content = generate_singbox_config(final_domain, uuid_str)
        SINGBOX_CONFIG_FILE.write_text(singbox_config_content)
        return True, links_output
    except Exception as e: return False, f"安装过程中发生意外错误: {e}"

def _start_services():
    if not CONFIG_FILE.exists(): return
    config = json.loads(CONFIG_FILE.read_text())
    port_vm_ws, argo_token = config["port_vm_ws"], config.get("argo_token")
    singbox_path, cloudflared_path = INSTALL_DIR / "sing-box", INSTALL_DIR / "cloudflared"

    with open(SB_LOG_FILE, "w") as sb_log:
        sb_process = subprocess.Popen([str(singbox_path), 'run', '-c', 'sb.json'], cwd=INSTALL_DIR, stdout=sb_log, stderr=subprocess.STDOUT)
    SB_PID_FILE.write_text(str(sb_process.pid))
    
    ### 核心修复: 强制为临时隧道启用 http2 协议 ###
    if argo_token:
        cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate', 'run', '--token', argo_token]
    else:
        cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate', '--url', f'http://localhost:{port_vm_ws}', '--protocol', 'http2']
    
    with open(LOG_FILE, "w") as cf_log:
        cf_process = subprocess.Popen(cf_cmd, cwd=INSTALL_DIR, stdout=cf_log, stderr=subprocess.STDOUT)
    ARGO_PID_FILE.write_text(str(cf_process.pid))

def _stop_services():
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
    _stop_services()
    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
    return "✅ 卸载完成。所有配置和进程已清除。请刷新页面以重新配置。"

def check_status_modified():
    if not CONFIG_FILE.exists(): return "服务未安装。"
    try:
        sb_pid = SB_PID_FILE.read_text().strip() if SB_PID_FILE.exists() else None
        cf_pid = ARGO_PID_FILE.read_text().strip() if ARGO_PID_FILE.exists() else None
        sb_running = sb_pid and subprocess.run(f"ps -p {sb_pid}", shell=True, capture_output=True).returncode == 0
        cf_running = cf_pid and subprocess.run(f"ps -p {cf_pid}", shell=True, capture_output=True).returncode == 0
        if sb_running and cf_running:
            return f"✅ **服务正在运行中**\n\n---\n" + (LIST_FILE.read_text() if LIST_FILE.exists() else "节点信息文件丢失。")
        else:
            status = ["❌ **服务状态异常**", f"  - sing-box: {'正常' if sb_running else '未运行'}", f"  - cloudflared: {'正常' if cf_running else '未运行'}"]
            return "\n".join(status)
    except Exception: return "检查状态时出错。"

def health_check_and_heal():
    if not CONFIG_FILE.exists(): return "服务未安装，跳过健康检查。"
    messages = []
    try:
        if not (SB_PID_FILE.exists() and subprocess.run(f"ps -p {SB_PID_FILE.read_text().strip()}", shell=True, capture_output=True).returncode == 0):
            messages.append("⚠️ sing-box 停止, 尝试重启...")
            with open(SB_LOG_FILE, "a") as log:
                p = subprocess.Popen([str(INSTALL_DIR / "sing-box"), 'run', '-c', 'sb.json'], cwd=INSTALL_DIR, stdout=log, stderr=subprocess.STDOUT)
            SB_PID_FILE.write_text(str(p.pid))
            messages.append("✅ sing-box 重启指令已发送。")

        if not (ARGO_PID_FILE.exists() and subprocess.run(f"ps -p {ARGO_PID_FILE.read_text().strip()}", shell=True, capture_output=True).returncode == 0):
            messages.append("⚠️ cloudflared 停止, 尝试重启...")
            config = json.loads(CONFIG_FILE.read_text())
            port_vm_ws, argo_token = config["port_vm_ws"], config.get("argo_token")
            cf_cmd = [str(INSTALL_DIR/"cloudflared"), 'tunnel', '--no-autoupdate', 'run', '--token', argo_token] if argo_token else [str(INSTALL_DIR/"cloudflared"), 'tunnel', '--no-autoupdate', '--url', f'http://localhost:{port_vm_ws}', '--protocol', 'http2']
            with open(LOG_FILE, "a") as log:
                p = subprocess.Popen(cf_cmd, cwd=INSTALL_DIR, stdout=log, stderr=subprocess.STDOUT)
            ARGO_PID_FILE.write_text(str(p.pid))
            messages.append("✅ cloudflared 重启指令已发送。")
    except Exception as e:
        messages.append(f"自愈检查时发生错误: {e}")
    return "\n".join(messages) if messages else f"✅ 健康检查通过，服务均在运行。({datetime.now().strftime('%H:%M:%S')})"

# --- UI 渲染函数 ---

def render_password_setup_ui():
    st.set_page_config(page_title="首次设置", layout="centered")
    st.title("🔐 首次运行 - 请设置密码")
    st.info("您需要设置一个主访问密码和一个节点查看密码。请务必牢记！")
    with st.form("password_setup_form"):
        secret_key_in = st.text_input("设置主访问密码", type="password")
        secret_key_confirm = st.text_input("确认主访问密码", type="password")
        st.markdown("---")
        node_password_in = st.text_input("设置节点查看密码", type="password")
        node_password_confirm = st.text_input("确认节点查看密码", type="password")
        submitted = st.form_submit_button("保存密码并继续")
        if submitted:
            if not all([secret_key_in, node_password_in]): st.error("所有密码字段都不能为空！")
            elif secret_key_in != secret_key_confirm: st.error("两次输入的主访问密码不匹配！")
            elif node_password_in != node_password_confirm: st.error("两次输入的节点查看密码不匹配！")
            else:
                if not INSTALL_DIR.exists(): INSTALL_DIR.mkdir(parents=True, exist_ok=True)
                SECRETS_FILE.write_text(json.dumps({"secret_key": secret_key_in, "node_view_password": node_password_in}, indent=2))
                st.success("密码已保存！页面将自动刷新..."); time.sleep(2); st.rerun()

def render_real_ui():
    st.set_page_config(page_title="部署工具", layout="wide")
    st.header("⚙️ 服务配置与管理")
    if 'output' in st.session_state and st.session_state.output:
        st.code(st.session_state.output); st.session_state.output = ""
    with st.spinner("正在执行健康检查..."): st.info(health_check_and_heal())
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("控制面板")
        if not CONFIG_FILE.exists():
            with st.form("config_form"):
                st.write("首次安装，请输入配置：")
                uuid_str_in = st.text_input("UUID", help="留空则自动生成")
                port_vm_ws_in = st.number_input("本地端口", min_value=0, max_value=65535, value=0, help="0则随机生成")
                st.markdown("---")
                st.write("如需使用Cloudflare Zero Trust隧道，请填写：")
                custom_domain_in = st.text_input("你的域名")
                argo_token_in = st.text_input("Argo Tunnel Token", type="password")
                if st.form_submit_button("保存并启动"):
                    with st.spinner("正在执行安装/启动流程..."):
                        success, message = install_or_start_modified(uuid_str_in, port_vm_ws_in, custom_domain_in, argo_token_in)
                        st.session_state.output = message
                        if not success: st.error(message)
                        st.rerun()
        else:
            st.success("已检测到固定配置。")
            if st.button("🔄 卸载并重装 (更新配置)", use_container_width=True):
                with st.spinner("正在卸载并重新安装..."):
                    uninstall_modified(); time.sleep(2)
                    success, message = install_or_start_modified(None, None, None, None)
                    st.session_state.output = "✅ 服务重装并更新配置文件成功。" if success else f"❌ 重装失败: {message}"
                    st.rerun()
            if st.button("❌ 永久卸载", type="primary", use_container_width=True):
                 with st.spinner("正在卸载..."):
                    st.session_state.output = uninstall_modified()
                    st.rerun()
    with col2:
        st.subheader("节点信息")
        st.warning("节点信息包含敏感数据，已被加密隐藏。")
        with st.expander("🔑 解密并查看节点信息"):
            password = st.text_input("请输入节点查看密码", type="password", key="node_password_input")
            if st.button("确认", key="submit_node_password"):
                if password == NODE_VIEW_PASSWORD:
                    st.session_state.node_info_unlocked = True; st.rerun()
                else: st.error("密码错误！")

def render_node_info_page():
    st.set_page_config(page_title="节点信息", layout="wide")
    st.title("🚀 节点信息详情")
    st.info("请及时复制所需信息。离开此页面后将需要重新验证。")
    st.markdown(check_status_modified(), unsafe_allow_html=True)
    st.markdown("---")
    
    with st.expander("📥 下载 sing-box 客户端配置文件 (推荐)", expanded=True):
        if SINGBOX_CONFIG_FILE.exists():
            config_content = SINGBOX_CONFIG_FILE.read_text()
            st.caption("提示: 此配置文件已包含所有节点，可直接导入 SFA/SFM 等客户端使用。")
            st.code(config_content, language="json")
            st.download_button(label="下载 config.json", data=config_content.encode('utf-8'), file_name="config.json", mime="application/json")
        else: st.warning("客户端配置文件不存在，请尝试重装服务以重新生成。")
    
    with st.expander("📋 复制 Vmess 节点链接 (兼容其他客户端)"):
        if ALL_NODES_FILE.exists():
            st.code(ALL_NODES_FILE.read_text(), language="text")
        else: st.warning("Vmess链接文件不存在。")

    st.markdown("---")
    if st.button("返回并锁定 🔐", type="primary"):
        st.session_state.node_info_unlocked = False; st.rerun()

def render_fake_ui():
    st.set_page_config(page_title="天气查询", layout="centered")
    st.title("🌦️ 实时天气查询")
    st.write("一个简单的天气查询工具。")
    city = st.text_input("请输入城市名或秘密口令：", "Beijing")
    if st.button("查询天气"):
        if city == SECRET_KEY:
            st.session_state.authenticated = True; st.rerun()
        else:
            with st.spinner(f"正在查询 {city} 的天气..."):
                time.sleep(1); st.error(random.choice(["查询失败", "API密钥过期", "网络超时"]))
    st.markdown("---"); st.info("这是一个开源项目。")

def main():
    st.session_state.setdefault('authenticated', False)
    st.session_state.setdefault('node_info_unlocked', False)
    st.session_state.setdefault('output', "")
    
    global SECRET_KEY, NODE_VIEW_PASSWORD
    if not SECRETS_FILE.exists():
        render_password_setup_ui(); return
    try:
        secrets = json.loads(SECRETS_FILE.read_text())
        SECRET_KEY, NODE_VIEW_PASSWORD = secrets.get("secret_key"), secrets.get("node_view_password")
        if not all([SECRET_KEY, NODE_VIEW_PASSWORD]):
            st.error("密码文件损坏，请删除 `.agsb/secrets.json` 后刷新重置。"); return
    except Exception as e:
        st.error(f"加载密码文件失败: {e}。请删除 `.agsb/secrets.json` 后刷新重置。"); return
    
    if st.session_state.authenticated:
        if st.session_state.node_info_unlocked: render_node_info_page()
        else: render_real_ui()
    else: render_fake_ui()

if __name__ == "__main__":
    main()