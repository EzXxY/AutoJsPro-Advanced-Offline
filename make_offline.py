#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 AutojsPro_original 生成无联网权限、无启动联网门禁的构建目录。"""

from __future__ import annotations

import argparse
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path


BASE = Path(__file__).resolve().parent
ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_NAME = f"{{{ANDROID_NS}}}name"

NETWORK_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE",
    "android.permission.BIND_VPN_SERVICE",
}

NETWORK_COMPONENTS = {
    "com.tencent.bugly.beta.ui.BetaActiveAlertActivity",
    "com.tencent.bugly.beta.ui.BetaActivity",
    "com.tencent.bugly.beta.utils.BuglyFileProvider",
    "com.tencent.bugly.beta.tinker.TinkerResultService",
    "com.flurry.android.agent.FlurryContentProvider",
}


def replace_once(text: str, old: str, new: str, description: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{description}: 预期匹配 1 次，实际匹配 {count} 次")
    return text.replace(old, new, 1)


def replace_method(text: str, signature: str, replacement: str) -> str:
    pattern = re.compile(
        rf"(?ms)^\.method {re.escape(signature)}\r?\n.*?^\.end method\s*"
    )
    text, count = pattern.subn(replacement.rstrip() + "\n\n", text, count=1)
    if count != 1:
        raise RuntimeError(f"未能唯一定位 smali 方法: {signature}")
    return text


def patch_manifest(path: Path) -> None:
    ET.register_namespace("android", ANDROID_NS)
    tree = ET.parse(path)
    root = tree.getroot()

    for child in list(root):
        if child.tag == "uses-permission" and child.get(ANDROID_NAME) in NETWORK_PERMISSIONS:
            root.remove(child)

    application = root.find("application")
    if application is None:
        raise RuntimeError("AndroidManifest.xml 中没有 application 节点")

    for child in list(application):
        if child.get(ANDROID_NAME) in NETWORK_COMPONENTS:
            application.remove(child)

    application.attrib.pop(f"{{{ANDROID_NS}}}usesCleartextTraffic", None)
    application.set(f"{{{ANDROID_NS}}}label", "AutoJsPro Offline")
    tree.write(path, encoding="utf-8", xml_declaration=True)

    # 重新解析并做强校验，防止上游结构变化后产出一个仍带联网权限的 APK。
    check_root = ET.parse(path).getroot()
    remaining_permissions = {
        node.get(ANDROID_NAME)
        for node in check_root.findall("uses-permission")
    }
    forbidden = NETWORK_PERMISSIONS & remaining_permissions
    if forbidden:
        raise RuntimeError(f"联网权限移除失败: {sorted(forbidden)}")

    check_app = check_root.find("application")
    assert check_app is not None
    remaining_components = {
        node.get(ANDROID_NAME)
        for node in list(check_app)
    }
    forbidden_components = NETWORK_COMPONENTS & remaining_components
    if forbidden_components:
        raise RuntimeError(f"联网组件移除失败: {sorted(forbidden_components)}")


def patch_app(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "    invoke-static {p0}, Lcom/wuyunai/NativeBridge;->startProxyIfActivated(Landroid/content/Context;)V\n\n",
        "",
        "移除本地 TCP 代理启动逻辑",
    )
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_splash(path: Path) -> None:
    text = path.read_text(encoding="utf-8")

    # 原离线补丁首次启动会创建本地 TCP 代理。无 INTERNET 权限时该代理无法工作，
    # 因此直接进入应用自身的条款/启动流程，不再进入代理激活对话框。
    text = replace_method(
        text,
        "public final ޠ()V",
        """.method public final ޠ()V
    .locals 1

    const/4 v0, 0x0

    iput-boolean v0, p0, Lorg/autojs/autojs/ui/splash/SplashActivity;->ၯ:Z

    invoke-virtual {p0, v0}, Lorg/autojs/autojs/ui/splash/SplashActivity;->afterActivationGate(Landroid/os/Bundle;)V

    return-void
.end method""",
    )

    # 禁用 Bugly/Huawei 自动更新检查，只保留原有的延迟跳转主界面逻辑。
    text = replace_method(
        text,
        "public final continueSplash()V",
        """.method public final continueSplash()V
    .locals 1

    invoke-virtual {p0}, Lorg/autojs/autojs/ui/splash/SplashActivity;->ޞ()V

    return-void
.end method""",
    )

    path.write_text(text, encoding="utf-8", newline="\n")


def patch_apktool_yml(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = text.replace("versionName: Pro 9.3.11-0", "versionName: Pro 9.3.11-0 Offline")
    text = re.sub(r"(?m)^- assets/original\.apk\r?\n?", "", text)
    path.write_text(text, encoding="utf-8", newline="\n")


def assert_clean_baseline(source: Path) -> None:
    forbidden = [
        source / "lib" / "arm64-v8a" / "libcoreprotect.so",
        source / "lib" / "arm64-v8a" / "libcorevmp.so",
        source / "smali_classes4" / "com" / "stardust" / "autojs" / "core" / "vpntrust.smali",
    ]
    present = [str(path.relative_to(source)) for path in forbidden if path.exists()]
    if present:
        raise RuntimeError(
            "拒绝从含在线校验注入的基线生成离线版: " + ", ".join(present)
        )


def verify_output(output: Path) -> None:
    manifest = output / "AndroidManifest.xml"
    root = ET.parse(manifest).getroot()
    permissions = {
        node.get(ANDROID_NAME)
        for node in root.findall("uses-permission")
    }
    if "android.permission.INTERNET" in permissions:
        raise RuntimeError("离线工程仍声明 android.permission.INTERNET")

    app_text = (output / "smali" / "org" / "autojs" / "autojs" / "App.smali").read_text(
        encoding="utf-8"
    )
    if "startProxyIfActivated" in app_text:
        raise RuntimeError("离线工程仍会启动 NativeBridge TCP 代理")

    splash_text = (
        output / "smali" / "org" / "autojs" / "autojs" / "ui" / "splash" / "SplashActivity.smali"
    ).read_text(encoding="utf-8")
    forbidden_calls = [
        "NativeBridge;->showFirstRunDialog",
        "Beta;->checkUpgrade",
        "UpdateSdkAPI;->checkAppUpdate",
        "vpntrust;->first",
    ]
    found = [value for value in forbidden_calls if value in splash_text]
    if found:
        raise RuntimeError("SplashActivity 仍包含联网启动调用: " + ", ".join(found))


def main() -> int:
    parser = argparse.ArgumentParser(description="生成 AutoJsPro 完全离线 apktool 工程")
    parser.add_argument("--source", default="AutojsPro_original", help="源 apktool 工程")
    parser.add_argument("--output", default=".build/AutojsPro_offline", help="输出目录")
    args = parser.parse_args()

    source = (BASE / args.source).resolve()
    output = (BASE / args.output).resolve()
    if not source.is_dir():
        raise RuntimeError(f"源目录不存在: {source}")
    if output == source or source in output.parents:
        raise RuntimeError("输出目录不能等于或位于源目录内部")

    assert_clean_baseline(source)
    if output.exists():
        shutil.rmtree(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, output, ignore=shutil.ignore_patterns("build", "original.apk"))

    patch_manifest(output / "AndroidManifest.xml")
    patch_app(output / "smali" / "org" / "autojs" / "autojs" / "App.smali")
    patch_splash(
        output / "smali" / "org" / "autojs" / "autojs" / "ui" / "splash" / "SplashActivity.smali"
    )
    patch_apktool_yml(output / "apktool.yml")
    verify_output(output)

    print(f"离线工程已生成: {output.relative_to(BASE)}")
    print("已移除 INTERNET/网络状态/Wi-Fi/VPN 权限、启动代理、在线校验入口和自动更新检查。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
