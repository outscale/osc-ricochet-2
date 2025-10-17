
# osc-ricochet-2

[![Project Sandbox](https://docs.outscale.com/fr/userguide/_images/Project-Sandbox-yellow.svg)](https://docs.outscale.com/en/userguide/Open-Source-Projects.html) [![](https://dcbadge.limes.pink/api/server/HUVtY5gT6s?style=flat\&theme=default-inverted)](https://discord.gg/HUVtY5gT6s)

<p align="center">
  <img alt="osc-ricochet-2 logo" src="https://img.icons8.com/?size=100&id=5XSGRTciGH5u&format=png&color=000000" width="100px">
</p>

---

## 🌐 Links

* Documentation: [https://docs.outscale.com/en/](https://docs.outscale.com/en/)
* Project website: [https://github.com/outscale/osc-ricochet-2](https://github.com/outscale/osc-ricochet-2)
* Join our community on [Discord](https://discord.gg/HUVtY5gT6s)
* Example configs: [`ricochet.json`](./ricochet.json), [`ricochet-headarches.json`](./ricochet-headarches.json)

---

## 📄 Table of Contents

* [Overview](#-overview)
* [Requirements](#-requirements)
* [Installation](#-installation)
* [Configuration](#-configuration)
* [Usage](#-usage)
* [Examples](#-examples)
* [License](#-license)
* [Contributing](#-contributing)

---

## 🧭 Overview

**osc-ricochet-2** is a lightweight “ricochet” service that accepts API-like requests and can send results back “from where they came,” enabling quick local testing, mocking, or demo scenarios without hitting the real OUTSCALE API.

> ⚠️ Expecting results identical to the OUTSCALE API may have unforeseen consequences. Use at your own risk.

---

## ✅ Requirements

* Rust & Cargo (stable toolchain recommended)
* Git
* (Optional) OUTSCALE credentials if you plan to mirror real-like identities

---

## ⚙ Installation

### Option 1: Download from Releases

Download the latest binary from the [Releases page](https://github.com/outscale/osc-ricochet-2/releases).

### Option 2: Install from source

```bash
git clone https://github.com/outscale/osc-ricochet-2.git
cd osc-ricochet-2
cargo build --release
```

---

## 🛠 Configuration

The first argument to `ricochet` is the path to the configuration file.

### Minimal example

```json
{
  "auth_type": "mix",
  "tls": false,
  "in_convertion": true,
  "password_as_ak": true,
  "users": [
    {
      "access_key": "11112211111110000000",
      "secret_key": "0000001111112222223333334444445555555666",
      "login": "joe",
      "pass": "ashita wa dochida"
    }
  ],
  "log": {
    "scope": ["nets", "vms"],
    "dir": "all"
  }
}
```

**Auth modes**

* `none`: no authentication.
* `exist`: verify user exists, skip deeper checks.
* `mix`: check password but skip V4 signature.
* `full`: full auth (experimental/buggy).

**Logging**

* `"scope"`: which resources to log (e.g., `["nets"]`, `["vms"]`, or both).
* `"dir"`: which direction(s) to log — `"in"`, `"out"`, or `"all"`.

---

## 🚀 Usage

Build and run with your config:

```bash
cargo run -- CONFIG.json
```

---

## 💡 Examples

### Adjust logs via API

```bash
curl 127.0.0.1:3000/SetLog_ -d '{"log": {"scope": ["vms"], "dir": "out"}}'
```

### “Ricochet” flow (ASCII)

```
[oapi-cli]
    |
    V
(createVms)    ->    [ricochet-2]
                           |
                           V
                     (create a VM)
                           |
                           V
[oapi-cli]    <----   (Send return)
    |
    V
(Print Result)
------- Some time later with a different client ----
 [curl]
    |
    V
(ReadVms)      ->    [ricochet-2]
                         |
                         V
 [curl]     <- (Send earlier created VM)
    |
    V
(print result)
```

---

## 📜 License

**osc-ricochet-2** is released under the BSD 3-Clause license.

© 2025 Outscale SAS

See [LICENSE](./LICENSE) for full details.

---

## 🤝 Contributing

We welcome contributions!

Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before submitting a pull request.
