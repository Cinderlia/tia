# impl

TIA 的实现包。设计口径见上游设计资料（`tia-design-kit/`，不纳入版本库）
与 [`docs/decisions.md`](../docs/decisions.md)。

```bash
uv sync
uv run pytest -q
uv run ruff check src tests && uv run mypy src
uv run tia-server --profile trigger
```

进程在测试容器的项目目录内运行（容器与挂载路径属于本地环境，不写进仓库）：

```bash
cd <repo>/impl
uv sync
```
