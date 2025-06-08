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

# --- 辅助函数 ---
def http_get(url, timeout=10):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as response:
            return response.read().decode('utf-8')
    except Exception:
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
    except Exception:
        return False

def generate_vmess_link(config):
    vmess_obj = {
        "v": "2", "ps": config.get("ps", "ArgoSB-TLS"), "add": config.get("add", ""),
        "port": str(config.get("port", "443")), "id": config.get("id", ""), "aid": "0",
        "net": "ws", "type": "none", "host": config.get("host", ""), "path": config.get("path", ""),
        "tls": "tls", "sni": config.get("sni", "")
    }
    vmess_str = json.dumps(vmess_obj, sort_keys=True)
    return f"vmess://{base64.b64encode(vmess_str.encode('utf-8')).decode('utf-8').rstrip('=')}"

def get_tunnel_domain():
    for _ in range(15): # 尝试15次，总共约30秒
        if LOG_FILE.exists():
            try:
                log_content = LOG_FILE.read_text()
                match = re.search(r'https://([a-zA-Z0-9.-]+\.trycloudflare\.com)', log_content)
                if match:
                    return match.group(1)
            except Exception:
                pass
        time.sleep(2)
    return None

# --- 核心逻辑函数 (适配无SSH、隐私优先的环境) ---

def generate_links_modified(domain, port_vm_ws, uuid_str):
    """只生成TLS节点，不上传"""
    output = []
    ws_path = f"/{uuid_str[:8]}-vm"
    ws_path_full = f"{ws_path}?ed=2048"
    hostname = socket.gethostname()[:10]
    all_links = []
    
    # 只保留TLS优选IP和端口
    cf_ips_tls = {
        "104.16.0.0": "443", "104.17.0.0": "8443", "104.18.0.0": "2053",
        "104.19.0.0": "2083", "104.20.0.0": "2087"
    }
    
    # 生成优选IP节点
    for ip, port in cf_ips_tls.items():
        config = {
            "ps": f"VMWS-TLS-{hostname}-{ip.split('.')[2]}-{port}", "add": ip, "port": port,
            "id": uuid_str, "host": domain, "path": ws_path_full, "sni": domain
        }
        all_links.append(generate_vmess_link(config))
    
    # 生成直连域名节点
    config_direct = {
        "ps": f"VMWS-TLS-Direct-{hostname}", "add": domain, "port": "443",
        "id": uuid_str, "host": domain, "path": ws_path_full, "sni": domain
    }
    all_links.append(generate_vmess_link(config_direct))

    # 保存纯链接到文件，方便复制
    (INSTALL_DIR / "allnodes.txt").write_text("\n".join(all_links) + "\n")
    CUSTOM_DOMAIN_FILE.write_text(domain)
    
    # 准备要在UI上显示的输出内容
    output.append("✅ **服务启动成功! (仅TLS节点)**")
    output.append("---")
    output.append(f"**域名 (Domain):** `{domain}`")
    output.append(f"**UUID:** `{uuid_str}`")
    output.append(f"**本地Vmess端口:** `{port_vm_ws}`")
    output.append(f"**WebSocket路径:** `{ws_path_full}`")
    output.append("---")
    output.append("**所有节点链接 (可直接复制):**")
    output.extend(all_links)
    
    # 将格式化的内容也保存到文件，用于状态检查
    list_content_for_file = [line.replace('`', '').replace('*', '') for line in output]
    LIST_FILE.write_text("\n".join(list_content_for_file))
    
    return "\n".join(output)

def install_or_start_modified(uuid_str_in, port_vm_ws_in, custom_domain_in, argo_token_in):
    output_log = []
    try:
        if not INSTALL_DIR.exists():
            INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        os.chdir(INSTALL_DIR)
        
        # --- 确定配置 (持久化) ---
        if CONFIG_FILE.exists():
            output_log.append("发现现有配置，将使用旧配置。")
            config = json.loads(CONFIG_FILE.read_text())
        else:
            output_log.append("未发现配置，将创建新配置。")
            config = {
                "uuid_str": uuid_str_in or str(uuid.uuid4()),
                "port_vm_ws": port_vm_ws_in or random.randint(10000, 65535),
                "custom_domain_agn": custom_domain_in,
                "argo_token": argo_token_in
            }
            CONFIG_FILE.write_text(json.dumps(config, indent=2))
        
        # 从最终确定的配置中读取变量
        uuid_str = config["uuid_str"]
        port_vm_ws = config["port_vm_ws"]
        custom_domain = config.get("custom_domain_agn")
        argo_token = config.get("argo_token")

        # --- 下载依赖 (如果不存在) ---
        system = platform.system().lower()
        machine = platform.machine().lower()
        arch = "amd64" if "x86_64" in machine else "arm64" if "aarch64" in machine else "amd64"
        
        singbox_path = INSTALL_DIR / "sing-box"
        if not singbox_path.exists():
            output_log.append("正在下载 sing-box...")
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

        cloudflared_path = INSTALL_DIR / "cloudflared"
        if not cloudflared_path.exists():
            output_log.append("正在下载 cloudflared...")
            cf_arch = "arm" if arch == "armv7" else arch
            cf_url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}"
            if not download_file(cf_url, cloudflared_path): return False, "cloudflared 下载失败。"
            os.chmod(cloudflared_path, 0o755)

        # --- 创建配置文件和启动脚本 ---
        ws_path = f"/{uuid_str[:8]}-vm"
        sb_config = {"log": {"level": "info"}, "inbounds": [{"type": "vmess", "listen": "127.0.0.1", "listen_port": port_vm_ws, "users": [{"uuid": uuid_str, "alterId": 0}], "transport": {"type": "ws", "path": ws_path, "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}}], "outbounds": [{"type": "direct"}]}
        (INSTALL_DIR / "sb.json").write_text(json.dumps(sb_config, indent=2))

        (INSTALL_DIR / "start_sb.sh").write_text(f'#!/bin/bash\ncd {INSTALL_DIR.resolve()}\n./sing-box run -c sb.json > sb.log 2>&1 &\necho $! > {SB_PID_FILE.name}\n')
        os.chmod(INSTALL_DIR / "start_sb.sh", 0o755)
        
        ws_path_full = f"{ws_path}?ed=2048"
        if argo_token:
            cf_cmd = f"./cloudflared tunnel --no-autoupdate run --token {argo_token}"
        else:
            cf_cmd = f"./cloudflared tunnel --no-autoupdate --url http://localhost:{port_vm_ws}{ws_path_full} --edge-ip-version auto --protocol http2"
        
        (INSTALL_DIR / "start_cf.sh").write_text(f'#!/bin/bash\ncd {INSTALL_DIR.resolve()}\n{cf_cmd} > {LOG_FILE.name} 2>&1 &\necho $! > {ARGO_PID_FILE.name}\n')
        os.chmod(INSTALL_DIR / "start_cf.sh", 0o755)

        # --- 启动服务 ---
        output_log.append("正在启动服务...")
        subprocess.run(str(INSTALL_DIR / "start_sb.sh"), shell=True)
        subprocess.run(str(INSTALL_DIR / "start_cf.sh"), shell=True)
        output_log.append("服务启动命令已发送，等待5秒...")
        time.sleep(5)

        # --- 获取域名并生成链接 ---
        final_domain = custom_domain
        if not argo_token and not custom_domain:
            output_log.append("正在获取临时隧道域名...")
            final_domain = get_tunnel_domain()
            if not final_domain:
                return False, "\n".join(output_log) + "\n\n错误: 无法获取隧道域名。请检查日志或尝试手动指定域名。"
        
        if final_domain:
            links_output = generate_links_modified(final_domain, port_vm_ws, uuid_str)
            output_log.append("\n" + links_output)
        else:
            return False, "\n".join(output_log) + "\n\n错误: 最终域名未能确定，无法生成链接。"

        return True, "\n".join(output_log)

    except Exception as e:
        return False, f"安装过程中发生意外错误: {e}"

def uninstall_modified():
    output_log = []
    output_log.append("开始卸载服务...")
    
    # 停止进程
    for pid_file in [SB_PID_FILE, ARGO_PID_FILE]:
        if pid_file.exists():
            try:
                pid = pid_file.read_text().strip()
                if pid: subprocess.run(f"kill {pid}", shell=True, capture_output=True)
            except Exception: pass
    
    # 强制清理
    subprocess.run("pkill -9 -f 'sing-box run'", shell=True)
    subprocess.run("pkill -9 -f 'cloudflared tunnel'", shell=True)
    output_log.append("已尝试终止所有相关进程。")

    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
        output_log.append(f"安装目录 {INSTALL_DIR} 已完全删除。")
    
    output_log.append("卸载完成。")
    return "\n".join(output_log)

def check_status_modified():
    if not INSTALL_DIR.exists() or not CONFIG_FILE.exists():
        return "服务未安装。请填写配置并点击“安装/启动”。"
    
    try:
        sb_pid = SB_PID_FILE.read_text().strip() if SB_PID_FILE.exists() else None
        cf_pid = ARGO_PID_FILE.read_text().strip() if ARGO_PID_FILE.exists() else None
        
        # 在很多受限环境中/proc目录可能无法访问，做个兼容
        sb_running = False
        if sb_pid:
            result = subprocess.run(f"ps -p {sb_pid}", shell=True, capture_output=True)
            sb_running = result.returncode == 0

        cf_running = False
        if cf_pid:
            result = subprocess.run(f"ps -p {cf_pid}", shell=True, capture_output=True)
            cf_running = result.returncode == 0

        if sb_running and cf_running:
            if LIST_FILE.exists():
                return f"✅ **服务正在运行中**\n\n---\n" + LIST_FILE.read_text()
            else:
                return "✅ **服务正在运行中**\n但节点信息文件丢失，请尝试重启服务。"
        else:
            status = ["❌ **服务状态异常**"]
            if not sb_running: status.append("  - sing-box 未运行")
            if not cf_running: status.append("  - cloudflared 未运行")
            status.append("\n请尝试点击“安装/启动”按钮来恢复服务。")
            return "\n".join(status)

    except Exception:
        return "检查状态时发生错误。可能是环境限制。请尝试重启服务。"


# --- Streamlit UI ---
def main_streamlit():
    st.set_page_config(page_title="ArgoSB 部署工具", layout="wide")
    st.title("ArgoSB 部署面板 (隐私模式)")
    st.caption("此版本仅供个人使用，不上传任何信息，仅生成TLS节点。")

    if 'output' not in st.session_state:
        st.session_state.output = check_status_modified()

    col1, col2 = st.columns([1, 1.2])

    with col1:
        st.header("⚙️ 服务配置")
        st.info("首次运行时，请填写配置。之后将自动使用已保存的配置。如需修改，请先卸载。")
        
        # 只有在未安装时才显示输入框
        if not CONFIG_FILE.exists():
            with st.form("config_form"):
                uuid_str_in = st.text_input("UUID", help="强烈建议留空，程序会自动生成并固定保存")
                port_vm_ws_in = st.number_input("Vmess 本地端口", min_value=0, max_value=65535, value=0, help="留空或0则随机生成并固定保存")
                st.markdown("---")
                st.subheader("如需使用Cloudflare Zero Trust隧道，请填写以下两项：")
                custom_domain_in = st.text_input("你的域名 (例如 my.domain.com)", help="使用Argo Token时必需")
                argo_token_in = st.text_input("Argo Tunnel Token", type="password", help="留空则使用临时的 trycloudflare.com 域名")
                
                submitted = st.form_submit_button("保存并启动")
                if submitted:
                    with st.spinner("正在执行安装/启动流程..."):
                        success, message = install_or_start_modified(uuid_str_in, port_vm_ws_in, custom_domain_in, argo_token_in)
                        st.session_state.output = message
                        if success: st.success("操作成功！")
                        else: st.error("操作失败！")
                    st.experimental_rerun()
        else:
            st.success("已检测到配置文件，将使用固定配置启动服务。")
            
            if st.button("🔄 重启服务", use_container_width=True):
                with st.spinner("正在重启服务..."):
                    # 传入空值，函数会从文件加载配置
                    success, message = install_or_start_modified(None, None, None, None)
                    st.session_state.output = message
                    if success: st.success("重启成功！")
                    else: st.error("重启失败！")
                st.experimental_rerun()

            if st.button("卸载所有服务和配置", type="primary", use_container_width=True):
                 with st.spinner("正在卸载..."):
                    st.session_state.output = uninstall_modified()
                 st.success("卸载完成！请刷新页面以重新配置。")
                 st.experimental_rerun()


    with col2:
        st.header("🚀 状态与节点信息")
        
        if st.button("🔄 刷新状态"):
            st.session_state.output = check_status_modified()
            st.experimental_rerun()
        
        st.markdown(st.session_state.output, unsafe_allow_html=True)


if __name__ == "__main__":
    main_streamlit()