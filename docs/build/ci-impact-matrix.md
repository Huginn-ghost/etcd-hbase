# CI 影响范围矩阵

CI 在 PR 创建或更新时比较 PR base 与 head 的完整文件差异，再按代码依赖关系选择验证组。多个路径的验证集合取并集；文档与代码同时变更时，代码验证和文档差异校验都会运行。

主分支 push 和 merge queue 的 `checks_requested` 事件运行全部验证组。CI 不使用 workflow 级 `paths` 过滤，也不在 `codex/**` 分支 push 上重复触发全量验证。

## 路径映射

| 改动路径 | 运行的验证 |
| --- | --- |
| 仅 `*.md` | 文档差异空白校验（`git diff --check`） |
| Lease/Watch Java 源码、M4 Go 场景，以及 `config/examples/m4/**` 非 Markdown 样例 | M4（J40–J47，包含 J45–J47 Watch 验证） |
| `core/src/**/io/etcdhbase/core/request/**` | J06、M4 |
| `core/src/**/io/etcdhbase/core/scan/**` | J10、J11、M1、M3、M4 |
| `protocol/src/**`、`grpc/src/**` 协议或服务源码（内部 proto 规则除外） | J03、J04、J06、J07、J23、J24、M3、M4 |
| Java SPI/盐策略契约测试源码（`testkit/src/**`） | J08 |
| Go 客户端、RPC 类型或 wire 源码（`testkit/go/internal/{client,rpctypes,wire}/**`） | J03、J06、J07、M3、M4 |
| M3 Go 命令、对照或场景（`testkit/go/cmd/m3*`、`testkit/go/internal/{compare,scenario}/m3_*.go`） | M3 |
| M4 Go 命令、对照或场景（`testkit/go/cmd/m4*`、`testkit/go/internal/{compare,scenario}/m4_*.go`） | M4 |
| `spi/**`、`hbase/**`、`core/src/**/io/etcdhbase/core/{bytes,commit,kv,storage}/**`、`grpc/src/main/proto/etcdhbase/internal/**` | 全部 15 个验证组 |
| Maven POM、依赖锁、Go 模块锁、`.mvn/**`、`build/**`、`scripts/**`、Actions workflow/action | 全部 15 个验证组 |
| 未列出的路径、差异为空或差异无法完整取得 | 全部 15 个验证组 |

上表中的代码目录映射只适用于非 Markdown 文件。Markdown 文件只运行文档校验；同一个 PR 同时修改 Markdown 和代码时会合并两类验证。

完整验证组为 J03、J04、J05、J06、J07、J08、J09、J10、J11、J23、J24、J36-proof、M1、M3、M4。公共提交、事务提交和跨副本恢复中未明确覆盖的路径会按“未列出的路径”回退到完整验证。

## 缓存与必需门禁

需要 Maven 的验证组先依赖同一个 Maven 公共准备 job；准备 job 校验依赖缓存，随后验证组使用只读缓存并并行运行。JDK 归档缓存键由 `build/dependency-lock.json` 计算，缓存命中或下载后都会重新校验锁定 SHA-256。J09 作为完整公开构建验证保持独立，并使用同一锁定 JDK 归档缓存。

`CI · 所有验证组汇总` 是稳定的汇总检查。它验证影响范围计算成功、所有选中验证通过、未选中验证确实跳过，并检查按需运行的 Maven 准备和文档校验结果。要让它阻止合并，仓库分支保护需要将这个检查配置为必需项。不要用 workflow 级 `paths` 过滤替代此门禁，以免 PR 缺少检查。

影响映射由 `scripts/verify/ci_impact.py` 实现，并由 `scripts/verify/test_ci_impact.py` 覆盖。新增或移动代码时同步更新映射和用例；无法证明影响范围时保留全量回退。实际节省的 runner 时间需要按合并后的 job 时长统计，本矩阵不预估节省比例。
