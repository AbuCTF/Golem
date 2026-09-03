#!/usr/bin/env bash
set -euo pipefail

ANDROID_SDK_VERSION="11076708"
API_LEVEL=34
SYSTEM_IMAGE="system-images;android-${API_LEVEL};google_apis;x86_64"
GOLEM_DIR="$(cd "$(dirname "$0")" && pwd)"

info()  { echo "  [*] $*"; }
ok()    { echo "  [+] $*"; }
warn()  { echo "  [!] $*"; }
fail()  { echo "  [-] $*" >&2; }

pip_install() {
    local flags=""
    if pip3 install --help 2>&1 | grep -q "break-system-packages"; then
        flags="--break-system-packages"
    fi
    pip3 install $flags "$@"
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        local ids="$ID ${ID_LIKE:-}"
        DISTRO="unknown"
        for candidate in $ids; do
            case "$candidate" in
                arch|manjaro|endeavouros|garuda|artix|cachyos)
                    DISTRO="arch"; break ;;
                ubuntu|debian|linuxmint|pop|kali|parrot|elementary)
                    DISTRO="debian"; break ;;
                fedora|rhel|centos|rocky|alma|nobara)
                    DISTRO="fedora"; break ;;
                opensuse*|sles)
                    DISTRO="suse"; break ;;
                void)
                    DISTRO="void"; break ;;
                alpine)
                    DISTRO="alpine"; break ;;
            esac
        done
        DISTRO_NAME="$PRETTY_NAME"
    else
        DISTRO="unknown"
        DISTRO_NAME="unknown"
    fi
}

pkg_install() {
    case "$DISTRO" in
        arch)   sudo pacman -S --needed --noconfirm "$@" ;;
        debian) sudo apt-get update -qq && sudo apt-get install -y "$@" ;;
        fedora) sudo dnf install -y "$@" ;;
        suse)   sudo zypper install -y "$@" ;;
        void)   sudo xbps-install -y "$@" ;;
        alpine) sudo apk add "$@" ;;
        *)      fail "unsupported distro - install manually: $*"; return 1 ;;
    esac
}

install_system_deps() {
    info "installing system dependencies"
    case "$DISTRO" in
        arch)
            pkg_install base-devel python python-pip unzip wget curl \
                jdk17-openjdk android-tools openssl ;;
        debian)
            pkg_install build-essential python3 python3-pip python3-venv \
                unzip wget curl openjdk-17-jdk-headless adb openssl \
                libgl1 libc6 libstdc++6 libpulse0 libxkbfile1 \
                libxcomposite1 libxcursor1 libxi6 libxtst6 libxrandr2 \
                libnss3 libgoogle-perftools4 ;;
        fedora)
            pkg_install gcc python3 python3-pip python3-devel \
                unzip wget curl java-17-openjdk-headless android-tools \
                openssl mesa-libGL ;;
        suse)
            pkg_install python3 python3-pip python3-devel \
                unzip wget curl java-17-openjdk-headless openssl ;;
        void)
            pkg_install python3 python3-pip unzip wget curl \
                openjdk17-jre android-tools openssl ;;
        alpine)
            pkg_install python3 py3-pip unzip wget curl openjdk17-jre \
                openssl musl-dev gcc ;;
        *)
            warn "install manually: python3 pip java-17 adb unzip wget curl openssl"
            return 0 ;;
    esac
    ok "system deps"
}

setup_kvm() {
    info "checking kvm"
    if [ ! -e /dev/kvm ]; then
        warn "no /dev/kvm - emulator will run without hardware acceleration"
        warn "enable vt-x/amd-v in bios if available"
        return 0
    fi
    if [ -w /dev/kvm ]; then
        ok "kvm"
        return 0
    fi
    info "adding $USER to kvm group"
    case "$DISTRO" in
        debian) sudo apt-get install -y qemu-kvm 2>/dev/null || true ;;
    esac
    sudo usermod -aG kvm "$USER" 2>/dev/null || true
    if [ ! -w /dev/kvm ]; then
        echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666"' | \
            sudo tee /etc/udev/rules.d/99-kvm.rules > /dev/null
        sudo udevadm control --reload-rules 2>/dev/null || true
        sudo udevadm trigger 2>/dev/null || true
    fi
    warn "kvm group added - log out and back in to apply"
}

setup_android_sdk() {
    ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
    if [ -x "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]; then
        ok "android sdk already at $ANDROID_HOME"
    else
        info "installing android sdk to $ANDROID_HOME"
        mkdir -p "$ANDROID_HOME"
        local cmdtools_zip="/tmp/commandlinetools-linux.zip"
        if [ ! -f "$cmdtools_zip" ]; then
            info "downloading cmdline-tools"
            wget -q --show-progress -O "$cmdtools_zip" \
                "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_SDK_VERSION}_latest.zip"
        fi
        unzip -qo "$cmdtools_zip" -d "$ANDROID_HOME/cmdline-tools-tmp"
        mkdir -p "$ANDROID_HOME/cmdline-tools"
        rm -rf "$ANDROID_HOME/cmdline-tools/latest"
        mv "$ANDROID_HOME/cmdline-tools-tmp/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
        rm -rf "$ANDROID_HOME/cmdline-tools-tmp" "$cmdtools_zip"
        ok "cmdline-tools"
    fi

    export ANDROID_HOME
    export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

    info "accepting sdk licenses"
    yes | sdkmanager --licenses > /dev/null 2>&1 || true

    info "installing sdk packages"
    sdkmanager --install \
        "platform-tools" \
        "emulator" \
        "platforms;android-${API_LEVEL}" \
        "$SYSTEM_IMAGE" \
        2>&1 | grep -v "^\[" || true
    ok "android sdk"

    setup_shell_env
}

setup_shell_env() {
    local android_home="${ANDROID_HOME:-$HOME/Android/Sdk}"
    local env_block="
export ANDROID_HOME=\"$android_home\"
export PATH=\"\$ANDROID_HOME/cmdline-tools/latest/bin:\$ANDROID_HOME/platform-tools:\$ANDROID_HOME/emulator:\$PATH\"
"
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$rc" ] && ! grep -q "ANDROID_HOME" "$rc" 2>/dev/null; then
            echo "$env_block" >> "$rc"
            ok "added ANDROID_HOME to $(basename "$rc")"
        fi
    done
}

install_python_package() {
    info "installing golem"
    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3,10) else 1)" 2>/dev/null; then
        fail "python >= 3.10 required"
        return 1
    fi
    cd "$GOLEM_DIR"
    local venv_dir="$GOLEM_DIR/.venv"
    if python3 -c "import sys; exit(0 if hasattr(sys, '_base_executable') or __import__('sysconfig').get_path('stdlib').startswith('/usr') else 1)" 2>/dev/null \
       && [ -f /usr/lib/python3*/EXTERNALLY-MANAGED ] 2>/dev/null; then
        info "externally managed python detected - using venv"
        python3 -m venv "$venv_dir"
        source "$venv_dir/bin/activate"
        for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
            if [ -f "$rc" ] && ! grep -q "golem.*venv" "$rc" 2>/dev/null; then
                echo "source \"$venv_dir/bin/activate\"" >> "$rc"
                ok "added venv activation to $(basename "$rc")"
            fi
        done
    fi
    pip3 install -e ".[dev,proxy,mcp]" 2>&1 | tail -3
    ok "golem $(python3 -c 'from golem import __version__; print(__version__)')"
}

install_static_tools() {
    info "installing static analysis tools"
    local missing=()

    if ! command -v apktool &>/dev/null; then
        case "$DISTRO" in
            arch)   pkg_install apktool ;;
            debian) pkg_install apktool ;;
            *)      missing+=("apktool") ;;
        esac
    fi

    if ! command -v jadx &>/dev/null; then
        case "$DISTRO" in
            arch) pkg_install jadx ;;
            *)
                local jadx_ver="1.5.1"
                local jadx_zip="/tmp/jadx.zip"
                wget -q --show-progress -O "$jadx_zip" \
                    "https://github.com/skylot/jadx/releases/download/v${jadx_ver}/jadx-${jadx_ver}.zip"
                sudo mkdir -p /opt/jadx
                sudo unzip -qo "$jadx_zip" -d /opt/jadx
                sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
                sudo ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui
                rm -f "$jadx_zip"
                ;;
        esac
    fi

    python3 -c "import apkid" 2>/dev/null || pip_install apkid 2>&1 | tail -1 || true

    if [ ${#missing[@]} -gt 0 ]; then
        warn "install manually: ${missing[*]}"
    else
        ok "static tools"
    fi
}

verify_install() {
    info "verify"
    echo ""
    local pass=0 total=0

    check() {
        total=$((total + 1))
        if eval "$2" > /dev/null 2>&1; then
            ok "$1"; pass=$((pass + 1))
        else
            fail "$1"
        fi
    }

    check "python3"             "python3 -c 'import sys; exit(0 if sys.version_info >= (3,10) else 1)'"
    check "golem"               "golem --version"
    check "adb"                 "command -v adb"
    check "java"                "java -version"
    local sdk="${ANDROID_HOME:-$HOME/Android/Sdk}"
    check "sdkmanager"          "test -x '$sdk/cmdline-tools/latest/bin/sdkmanager' || command -v sdkmanager"
    check "avdmanager"          "test -x '$sdk/cmdline-tools/latest/bin/avdmanager' || command -v avdmanager"
    check "emulator"            "test -x '$sdk/emulator/emulator' || command -v emulator"
    check "kvm"                 "test -w /dev/kvm"
    check "system image"        "test -d '$sdk/system-images/android-${API_LEVEL}' || '$sdk/cmdline-tools/latest/bin/sdkmanager' --list_installed 2>/dev/null | grep -q 'system-images;android-${API_LEVEL}'"
    check "uiautomator2"        "python3 -c 'import uiautomator2'"
    check "frida"               "python3 -c 'import frida'"
    check "mitmproxy"           "command -v mitmdump"
    check "pillow"              "python3 -c 'from PIL import Image'"

    echo ""
    local opt_pass=0 opt_total=0
    opt_check() {
        opt_total=$((opt_total + 1))
        if eval "$2" > /dev/null 2>&1; then
            ok "$1"; opt_pass=$((opt_pass + 1))
        else
            warn "$1 - not installed"
        fi
    }

    opt_check "apktool"         "command -v apktool"
    opt_check "jadx"            "command -v jadx"
    opt_check "apkid"           "python3 -c 'import apkid'"

    echo ""
    if [ "$pass" -eq "$total" ]; then
        ok "core $pass/$total - ready"
    else
        warn "core $pass/$total - some components missing"
    fi
    info "optional $opt_pass/$opt_total"
    echo ""
}

main() {
    detect_distro
    info "distro: $DISTRO_NAME ($DISTRO)"

    local skip_system=false skip_sdk=false skip_static=false verify_only=false

    for arg in "$@"; do
        case "$arg" in
            --no-system)  skip_system=true ;;
            --no-sdk)     skip_sdk=true ;;
            --no-static)  skip_static=true ;;
            --verify)     verify_only=true ;;
            --help|-h)
                echo "usage: ./setup.sh [--no-system] [--no-sdk] [--no-static] [--verify]"
                return 0 ;;
        esac
    done

    if $verify_only; then
        verify_install
        return 0
    fi

    $skip_system || install_system_deps
    setup_kvm
    $skip_sdk || setup_android_sdk
    install_python_package
    $skip_static || install_static_tools
    verify_install
}

main "$@"
