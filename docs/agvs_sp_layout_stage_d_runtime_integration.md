# AGVS-SP 新布局 Stage D：运行时受控接入

日期：2026-07-29

## 结果

Stage C 验收通过后，新布局已经接入专业版与 Student 版网页运行路径。
专业版仍固定使用 v1.4 规则；Student 版仍固定使用独立的
`student-v1.2` 教学规则。本阶段没有修改任何报告抽取、证据判断、
ATT&CK Technique、Mitigation 或 likelihood 逻辑。

默认 PNG 路径现在是：

`AttackGraph → causal pagination → Visual IR → layout planner → router → PNG`

## 统一切换点

`src/attack_graph.py` 现在负责唯一的后端选择：

- 默认：`new`
- 临时回退：`legacy`
- 非法名称：立即抛出错误，不静默选择未验证后端

若真实报告测试发现尚未覆盖的布局问题，可以在启动 Flask 前设置：

```powershell
$env:AGVS_PNG_RENDERER = "legacy"
```

恢复新布局：

```powershell
$env:AGVS_PNG_RENDERER = "new"
```

或删除该环境变量后重启应用；缺省值就是 `new`。

回退开关只选择绘图后端，不改变 `AttackGraph` 数据。

## 专业版

`app.py` 继续执行：

1. 保存报告；
2. `ingest()`；
3. `extract_attack_graph(..., ruleset="v1.4")`；
4. 因果边界分页；
5. 新布局渲染；
6. 使用规则、模型及运行序号保存全部页面。

旧的 `Compact` 复选框已从页面删除，因为新布局的间距和分页由确定性
规划器自动控制。页面显示 `Layout: AGVS-SP branch-aware`。

## Student 版

`student_app.py` 保留自己的输入、证据规则、API 模型和 JSON audit。
唯一运行变化是：

- 单图 `render()` 改为统一的 `render_split()`；
- 小图仍生成一张；
- 长图按相同的因果状态边界生成多张；
- 网页会列出并显示全部分页；
- audit 仍保存一份完整、未分页的 canonical `AttackGraph` JSON。

因此，多页图可以由 audit 无损重建，分页不会变成新的语义模型。

## 自动测试

新增：

`tests/test_layout_stage_d_integration.py`

验证内容：

| 检查 | 结果 |
|---|---|
| 新布局是默认 PNG 后端 | 通过 |
| 显式 `renderer="new"` 只调用新后端 | 通过 |
| 显式 `renderer="legacy"` 只调用旧后端 | 通过 |
| 非法后端名称被拒绝 | 通过 |
| 环境变量可回退且不改变模型 | 通过 |
| 专业版仍把伪造的 v1.5 请求固定为 v1.4 | 通过 |
| 专业网页输出包含新 Stolen Pencil 配色 | 通过 |
| Student 长图自动分页 | 通过 |
| Student 网页显示所有分页 | 通过 |
| Student 完整 audit 只保存一次 | 通过 |

完整测试结果：**147 tests passed**。

冻结文件与 Stage A 前备份逐字节哈希一致：

- `rules/ruleset_v1.4.md`
- `src/schema.py`
- `src/extract.py`
- `data/attack_lookup.json`

## 离线端到端预览

预览实际经过 Flask `/generate` 路由，但使用 mock provider，没有产生
API 费用：

- `tmp/stage_d_runtime_previews/professional_outputs/`
- `tmp/stage_d_runtime_previews/student_outputs/`

## 尚未删除旧渲染器的原因

`reference_renderer.py` 暂时只作为回退后端保留。虽然结构测试、离线
网页测试和完整回归均已通过，但真实 LLM 输出可能包含 oracle 未覆盖的
罕见拓扑。建议先用 British Library、WannaCry、M&S 各执行一次真实
端到端布局验收；若没有新缺陷，再进入旧布局删除与代码清理阶段。
