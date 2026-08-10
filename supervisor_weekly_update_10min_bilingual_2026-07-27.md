# 10-Minute Weekly Supervisor Update / 10 分钟导师例会汇报

> 使用方式：会议中主要讲英文；中文是对应的理解稿，不需要中英文都读。  
> 预计英文讲解约 8 分钟，展示图片或界面约 1–1.5 分钟，最后留约 30 秒讨论。  
> 语气定位：weekly progress update，不是答辩。

---

## 0:00–0:45 Opening / 开场

### 中文理解

这周我主要完成了三件事：冻结专业版 v1.4；完成独立的 Student v1.2；
继续把输出格式优化得更接近导师 sample。同时，我修复了测试中暴露的
ATT&CK、证据验证和两阶段生成问题，并建立了 66 项离线回归测试。

### English script

This week I focused on three main areas. First, I froze Professional version 1.4 as
the dissertation baseline. Second, I completed a separate Student version, currently
student-v1.2. Third, I continued improving the visual output so that it is closer to
the sample graph. I also fixed several issues found during testing, particularly
around ATT&CK assignments, evidence validation and the two-stage generation process.
The project now has 66 passing offline regression tests.

---

## 0:45–2:00 Professional version / 专业版进展

### 中文理解

专业版现在固定使用 v1.4，不再允许通过网页切换规则。冻结的原因不是它已经
完美，而是它已经作为 British Library 开发案例以及 WannaCry、M&S 测试的
共同基线。继续改变它会破坏论文结果的可比较性。

专业版采用两阶段处理。Stage A 只识别前提、攻击动作、结果、连接关系和 tactic；
Stage B 只从该 tactic 的 ATT&CK 候选中选择 T/M。这样避免一次性从约 700 个
技术中搜索，也避免 Stage B 重新生成整张图而丢失节点。

### English script

The Professional application is now fixed to v1.4, and the rule set can no longer be
changed through the web form. I froze it not because it is perfect, but because it
has become the common baseline used for the British Library development case and
the WannaCry and M&S tests. Continuing to change it would reduce comparability
between the dissertation results.

The Professional pipeline uses two stages. Stage A identifies preconditions,
adversary actions, outcomes, graph relationships and ATT&CK tactics. Stage B then
selects techniques and mitigations only from candidates associated with those
tactics. This is more stable than asking the model to search nearly 700 techniques
in one response. Stage B also returns assignments only, rather than regenerating
the complete graph, so the Stage A structure cannot be accidentally lost.

---

## 2:00–4:15 Student version / Student 版本

### 中文理解

Student 版对应导师提出的要求：学生在文本框输入攻击描述，点击 Generate，
系统生成攻击图。它与专业版分离，但共享 Schema、ATT&CK 数据和渲染器。

Student 版更强调教学和证据：

- 只抽取攻击者动作；
- 受害者、警方、法院和恢复人员动作不能成为攻击 event；
- 每个 event 保存原文证据和动作短语；
- 报告只支持高层动作时，不猜测更具体技术；
- 证据不足时保留 event，但允许 T 为空；
- T 为空时 M 也必须为空；
- 不为了强制连通而编造动作或连接；
- 保存 PNG 和 evidence audit JSON。

Student 版本经历了从结构优先到证据优先的改变。早期强制每个事件都有前提和
结果，短新闻容易生成空图或产生推断。v1.1 放宽 root/terminal event 并加入
证据；v1.2 再加入 ATT&CK v19、T/M 关系和高风险技术证据门槛。

### English script

The Student version addresses the requirement that a student should be able to type
an incident description into a box, press Generate, and receive an attack graph. It
is separated from the Professional baseline, but it shares the same canonical
schema, ATT&CK catalogue and renderer.

The Student version places greater emphasis on teaching and evidence. It extracts
adversary actions only, so actions performed by victims, police, courts or recovery
teams should not become attack events. Each event stores its supporting source
quotation and action phrase. If the text supports only a high-level action, the
system should retain that action rather than inventing a more specific method.
Where there is insufficient evidence for a technique, the event can remain while
the technique is left blank. If the technique is blank, mitigations must also be
blank. The system also avoids inventing actions or edges merely to create a fully
connected graph.

The Student version therefore changed from a structure-first approach to an
evidence-first approach. The early version required every event to have both an
input state and an outcome, which caused short news reports either to fail or to
produce unsupported structure. Student v1.1 allowed root and terminal events and
introduced evidence fields. Student v1.2 then added ATT&CK v19 validation, official
technique-to-mitigation relationships and evidence thresholds for several common
over-mappings. Each run now saves both the PNG and an evidence-audit JSON file.

---

## 4:15–5:40 ATT&CK and validation / ATT&CK 与验证

### 中文理解

当前本地目录来自 MITRE Enterprise ATT&CK v19 官方 STIX 数据，包含 697 个
technique/sub-technique 和 44 个 mitigation。

Schema 会验证节点 id、parent、DAG、T/M 是否存在、T 是否属于 tactic，以及
T 为空时不能保留 M。Student v1.2 还验证 M 是否真的由 MITRE 定义为 mitigates
该 T，而不是只检查 M 编号是否合法。

盲测中反复出现的三个高价值错误被转换成通用证据门槛：

- 没有 RDP/SSH/SMB 等 remote-service 证据时，不使用 T1021；
- 没有伪装或冒充语义时，不使用 T1036；
- 只有明确禁用安全工具时才使用 T1685。

### English script

The local catalogue now comes from official MITRE Enterprise ATT&CK v19 STIX data
and contains 697 techniques and sub-techniques and 44 mitigations.

The schema validates node identifiers, parent references, graph acyclicity, the
existence of each technique and mitigation, and whether the technique belongs to the
event’s tactic. It also prevents mitigations from remaining when the technique is
blank. Student v1.2 goes further by checking whether MITRE officially defines the
selected mitigation as mitigating that particular technique, rather than checking
only that both identifiers exist.

Three recurring blind-test errors were converted into general evidence thresholds.
The system does not use T1021 without evidence of remote services such as RDP, SSH
or SMB. It does not use T1036 without evidence of disguise, spoofing or
impersonation. It uses T1685 only when the source clearly describes disabling or
modifying a security tool. These are general checks rather than hard-coded answers
for a particular organisation.

---

## 5:40–7:00 Sample format optimisation / Sample 格式优化

### 中文理解

图的视觉语法现在更接近导师 sample：

- 椭圆表示前提、状态或结果；
- 矩形表示攻击者动作；
- 粉红色右上角是 T；
- 橙色右下角是 M；
- 青色圆形是 likelihood；
- 紫色圆形是 tactic 或节点代码；
- 右侧只列本图用到的图例。

早期输出是一条很长的竖图。现在使用自定义 Pillow renderer、topological
order、默认每行四个节点、Compact 每行五个节点、横向折行和正交连接线。

AND/OR 不再用明显文字节点：线汇聚表示 AND，替代路径分开表示 OR；内部数据
仍保存 join 语义。

### English script

The visual syntax is now much closer to the supplied sample. Ellipses represent
preconditions, states or outcomes, while rectangles represent adversary actions.
Pink top-right badges show techniques, orange bottom-right badges show mitigations,
cyan circles show likelihood, and purple circles show tactics or state codes. The
legend on the right lists only the elements used in that graph.

Earlier outputs formed very long vertical diagrams. The custom Pillow renderer now
uses topological ordering, four nodes per row by default, five in Compact mode,
horizontal wrapping and orthogonal connectors.

The graph also follows the supervisor’s AND/OR syntax. It does not need to print the
words AND and OR. Converging connected lines represent AND, while separated
alternative paths represent OR. The join value is still preserved internally for
validation.

---

## 7:00–8:15 Problems fixed and testing / 已修复问题与测试

### 中文理解

这周处理的主要问题包括：

- Stage A 因规则冲突返回空 events；
- Stage B 重新生成图时丢失节点；
- T 属于错误 tactic；
- Claude 把 JSON 数组再次编码成字符串；
- retired ATT&CK id；
- `persuaded`、`accessing` 和被动语态匹配失败；
- 合法但与 T 无官方关系的 mitigation；
- Student 输入 mojibake；
- 重复运行覆盖历史图片；
- API 隐藏重试和成本不可控。

现在输出自动带规则、模型和运行序号，不覆盖历史结果。API 每次生成共享
0.45 美元上限，Claude SDK 自动重试关闭。

### English script

The main issues addressed this week included Stage A returning no events because of
conflicting constraints, Stage B losing nodes when it regenerated the graph,
techniques being assigned to the wrong tactic, JSON arrays being encoded as
strings, retired ATT&CK identifiers, evidence-matching failures involving words such
as `persuaded`, `accessing` and passive constructions, and mitigations that were
valid identifiers but had no official relationship to the technique.

I also added handling for damaged Student text encoding, non-overwriting output
names, and controlled API retries. Output filenames now include the rule set, model
and sequential run number. Each generation shares a US$0.45 cost limit, and hidden
automatic retries in the Claude SDK are disabled.

There are currently 66 offline regression tests, all passing. They cover the frozen
Professional baseline, Student input and evidence handling, graph and schema
validation, ATT&CK consistency, output naming, API cost controls and the main repair
mechanisms.

---

## 8:15–9:05 Current limitations / 当前限制

### 中文理解

系统不是完全正确的自动分析员。DPP 等测试仍然发现：

- 可能遗漏明确动作；
- 可能把两个动作合并；
- 可能推断原文没有明确说明的因果边；
- 可能把时间顺序加强成 AND 必要条件。

因此论文应把系统定义为可重复、可审计的 research/teaching prototype，输出
需要人工复核。这里没有对 Claude 做模型权重训练，准确说法是 iterative
prompt/rule engineering、structured extraction 和 deterministic validation。

### English script

The system is not a completely reliable automated analyst. More complex tests, such
as the DPP case, show that the model can still omit an explicit action, merge two
actions, infer a causal edge that the source does not state, or strengthen
chronology into an AND dependency.

I will therefore describe it as a repeatable and auditable research and teaching
prototype whose outputs require human review. I have not trained or fine-tuned the
Claude model weights. The accurate description is iterative prompt and rule
engineering, constrained structured extraction and deterministic validation.

---

## 9:05–9:40 Short demonstration / 简短展示

### 中文操作

只展示，不重新讲全部技术：

1. 展示 Professional 页面固定为 v1.4；
2. 展示一张已有专业图；
3. 打开 Student 页面，指出文本框和 Generate；
4. 展示一张 TfL Student 图；
5. 指出矩形、椭圆、T/M、likelihood 和 tactic；
6. 打开对应 evidence JSON，指出一个 event 的原文证据。

如果时间很紧，只展示 Student 图和 JSON。

### English narration

This is the frozen Professional interface, which is fixed to v1.4. This is one of
the existing Professional outputs. The separate Student interface provides a text
box and a Generate button. In this TfL result, the rectangles are adversary actions
and the ellipses are states or outcomes. The coloured badges show the ATT&CK and
likelihood information. The corresponding JSON file stores the supporting quotation
for each Student event, so the graph can be audited without putting long evidence
text inside the diagram.

---

## 9:40–10:00 Closing and discussion / 结束与讨论

### 中文理解

建议下一步冻结代码，开始写 methods、implementation、testing 和 limitations。
向导师确认 Student 应作为独立 artifact 评估，还是作为专业版的 educational
extension；以及 evidence 是否需要直接在网页显示。

### English script

My current recommendation is to keep Professional v1.4 and Student v1.2 frozen and
move the main effort to the methods, implementation, testing and limitations
chapters. I would like to confirm whether the Student version should be evaluated as
a separate artifact or presented as an educational extension of the Professional
prototype, and whether the evidence audit should remain in JSON or also be shown
directly in the interface.

---

## Meeting reminder / 例会提醒

日常例会中不需要主动展开以下内容，除非导师追问：

- 不逐条解释 v1.0–v1.5；
- 不逐个列出全部 66 项测试；
- 不详细解释每个 T/M；
- 不现场重新生成大型 PDF；
- 不说“模型已经完美”；
- 不把 prompt/rule iteration 称为 fine-tuning。

最重要的四句话：

1. Professional v1.4 is now frozen as the comparable research baseline.
2. Student v1.2 is a separate evidence-first teaching application.
3. The output now follows the sample visual syntax more closely.
4. The system is validated and auditable, but still requires human review.
