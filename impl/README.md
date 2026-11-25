# impl

TIA 的实现包。设计口径见仓库根目录的上游设计资料（`tia-design-kit/`，不纳入版本库）与 [`docs/environment.md`](../docs/environment.md)。

```bash
uv sync
uv run pytest -q
uv run ruff check src tests && uv run mypy src tests
uv run tia-server --profile trigger
```

进程只在 `php84-dev` 容器内运行：

```bash
docker exec --user root -w /home/so/tia/impl php84-dev bash
```
