# 开发与测试环境

> 本文件记录 TIA 开发所依赖的**外部环境事实**。环境变更时先改这里，再改代码。
> 最近核实：2026-11-25。

## 1. 机器与仓库

| 项 | 值 |
|---|---|
| 开发机 | `jmliang@172.28.8.69`（Linux，POSIX） |
| 项目根目录 | `/home/jmliang/tia` |
| 开发工作区 | `/home/jmliang/tia/dsh-workdir`（不提交） |
| 设计资料 | `/home/jmliang/tia/tia-design-kit`（不提交） |
| 远程仓库 | `git@github.com:Cinderlia/tia.git`（SSH，分支 `main`） |

## 2. 测试容器 `php84-dev`

容器内即测试环境；**所有 Python 包、apt 包的安装都必须在容器内进行**。

```bash
docker exec -it --user root -w /app php84-dev bash
```

| 项 | 值 |
|---|---|
| 镜像 | `php84-dev-backup:20261125-0628` |
| 系统 | Debian GNU/Linux 13 (trixie) |
| 身份 | 容器内 `root`（uid 0） |
| 端口映射 | `8008 -> 80`（Apache）、`3006 -> 3306`（MariaDB） |
| 挂载 | `/home/jmliang/tia -> /home/so/tia`（项目根目录在容器内可见） |
| 工作目录 | `/app` |

### 2.1 运行时

| 组件 | 版本 / 位置 | 备注 |
|---|---|---|
| PHP | 8.4.25（CLI + Apache 模块） | 扩展含 `mysqli` / `pdo_mysql` / `xdebug` / `curl` / `dom` / `mbstring` / `sqlite3` |
| Apache | 2.4.68 | `DocumentRoot /var/www/html`，该路径是 `/app` 的符号链接 |
| MariaDB | 本地 3306 | 容器内 `root` 空密码可直连；宿主端口 `3006` |
| Python | `/usr/bin/python3.13` = 3.13.5 | **注意**：`python3` 走 pyenv shim，默认 3.10.14（不满足 3.11+），调用时请显式用 `/usr/bin/python3.13`，或让 uv 管自己的解释器 |
| Composer | 2.11.2 | 供 `probe-php` 依赖使用 |
| Node.js | 未安装 | 当前设计不需要 |
| uv | 未安装 | 首次需在容器内安装 |

### 2.2 测试目标（容器内 `/app`）

| 应用 | 入口 | 数据库 |
|---|---|---|
| bWAPP | `http://127.0.0.1/bwapp/bWAPP/login.php` | `bWAPP`（`root` / 空密码） |
| DVWA | `http://127.0.0.1/dvwa/login.php` | `dvwa` |
| WeGIA | `http://127.0.0.1/WeGIA/` | `wegia` |
| phpMyFAQ | `http://127.0.0.1/phpmyfaq/` | `phpmyfaq` |
| CubeCart | `https://127.0.0.1:8443/cubecart` | `cubecart` |

从宿主机访问同一实例：`http://172.28.8.69:8008/...`；MySQL：`172.28.8.69:3006`。
TIA 以容器内视角运行：`base_url = http://127.0.0.1`，`dsn = root@127.0.0.1:3306`；若从宿主进程运行，则换成 `http://172.28.8.69:8008` / `172.28.8.69:3006`。

## 3. 本地模型（LLM）

OpenAI 兼容接口，**不计量、不限额度**，验证流程时可随意调用。

| 项 | 值 |
|---|---|
| Base URL | `http://172.28.8.100:8000/v1` |
| Model | `Qwen3.8-27B` |
| API Key | `sk-a-strong-key` |
| 上下文 | `max_model_len = 524288` |
| 特性 | 推理模型，返回带 `reasoning_content`；`/v1/models` 里的 id 是 `/data/models/Qwen3.8-27B`，请求时用 `Qwen3.8-27B` 即可 |

已验证：宿主机与 `php84-dev` 容器内均可访问（约 1–2 ms），`/v1/models` 与 `/v1/chat/completions` 均返回 200。

```bash
curl -s http://172.28.8.100:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-a-strong-key' \
  -d '{"model":"Qwen3.8-27B","messages":[{"role":"user","content":"ping"}],"max_tokens":32}'
```

TIA 中仅 planner / judge 使用该模型；配置写在 `impl/profiles/*.yaml` 的 `llm:` 段，不硬编码。

## 4. 依赖安装规约

换环境要能一键还原，因此：

1. **Python 依赖只认 `impl/pyproject.toml`**：需要新包时在容器内用 `uv add <pkg>`（或先改 `pyproject.toml` 再 `uv lock`），**不要**裸 `pip install` 后不留痕。`uv.lock` 一并提交。
2. **临时验证用的包**若不想进主依赖，写入 `impl/requirements-extra.txt`（带版本号与用途注释），并在本节记录。
3. **apt 包**写入 `impl/deploy/apt-packages.txt`（一行一个），由 `impl/scripts/bootstrap-container.sh` 幂等安装。
4. **PHP 采集器依赖**走 `impl/probe-php/composer.json` + `composer.lock`。
5. 每次环境变更在本文件「变更记录」追加一行：日期、装了什么、为什么。

```bash
# 容器内引导（T01 落地后可用）：安装 uv + Python 3.13 环境 + 全部依赖
docker exec --user root -w /app php84-dev bash /home/so/tia/impl/scripts/bootstrap-container.sh
```

`bootstrap-container.sh` 在 T01 一并落地；在此之前手工安装的包也必须补进上述清单。

### 变更记录

| 日期 | 变更 | 原因 |
|---|---|---|
| 2026-11-25 | 环境核实，尚未安装额外依赖 | 仓库初始化 |
