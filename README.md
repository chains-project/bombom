# bombom - System Package Information Collector

A powerful Python tool for generating Software Bill of Materials (SBOM) from your Linux system.

## 🚀 Features

- Collects package information from multiple sources:
  - System packages (dpkg)
  - Python packages (pip, pipx)
  - Applications (Flatpak, Docker)
  - Node.js packages (npm)
  - Snap packages
- Tracks system component versions:
  - Kernel
  - Browsers (Firefox, Chrome)
  - Development tools (VS Code)
  - System services (DBus, Systemd)
- Flexible output formats:
  - Individual text files
  - Combined tar archive

## 📋 Requirements

- Python 3.6+
- Linux system with any of these package managers:
  - apt/dpkg
  - pip
  - flatpak
  - snap
  - npm
  - docker

## 🔧 Installation

```bash
git clone https://github.com/monperrus/bombom.git
cd bombom
pip install -r requirements.txt
```

## 💻 Usage

Basic usage (saves files to `./__sbom__/`):
```
python bombom.py
```

Advanced usage :
```
python bombom.py --tar | tar xz -C /path/to/dest
```

## License

MIT

