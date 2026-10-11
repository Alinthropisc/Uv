# ⚡ AZULA — VERSIONS

> 🧬 **CORE DEPENDENCIES / TOOLCHAIN MATRIX**
>
> _Know your stack. Control your stack._

---

## 🧠 RUNTIME & PARSING

| ⚙️ Component | 🔖 Version |
|---|---:|
| 🐍 **liblua** | `5.5.1` |
| 🧩 **libpcre2** | `10.48` |

---

## 🌐 NETWORK & SECURITY

| ⚙️ Component | 🔖 Version |
|---|---:|
| 🔐 **libssh2** | `1.11.1` |
| 🕸️ **libpcap** | `1.10` |
| 🧨 **libdnet** | `1.18.2` |

---

## 🤖 ANALYSIS & COMPUTATION

| ⚙️ Component | 🔖 Version |
|---|---:|
| 📐 **liblinear** | `250` |

---

## ☠️ AZULA STACK

```text
                    ⚡ AZULA
                       │
          ┌────────────┴────────────┐
          │                         │
       🧠 Runtime              🌐 Network
          │                         │
      liblua 5.5.1             libpcap 1.10
      libpcre2 10.48           libdnet 1.18.2
                                  │
                              libssh2 1.11.1
          │
          └────────────┬────────────┘
                       │
                 🤖 Intelligence
                       │
                  liblinear 250
```

### 🔥 VERSION LOCK

```text
[ AZULA / DEPENDENCY MATRIX ]

Lua       :: 5.5.1
PCRE2     :: 10.48
SSH2      :: 1.11.1
PCAP      :: 1.10
Linear    :: 250
DNet      :: 1.18.2
```

## 💀 Dependencies are not decoration.

## ⚔️ Every version is a controlled component of the Azula stack.