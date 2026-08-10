项目结构说明
============
src/        代码(schema, ingest, extract, attack_graph, attack_lookup)
data/       ATT&CK 官方字典(由 scripts/update_attack_lookup.py 生成)
scripts/    工具脚本(更新 ATT&CK 字典)
reports/    <-- 把要检测的攻击报告 PDF 放这里
outputs/    <-- 生成的攻击图自动输出到这里,按报告名命名
examples/   示例脚本和示例 JSON
app.py      网页界面(python app.py -> 浏览器打开 127.0.0.1:5000)

命令行用法(和以前一样,但报告放 reports/、图输出到 outputs/):
  python examples/generate_from_report.py Case-Study_WannaCry.pdf anthropic claude-sonnet-5

网页用法:
  python app.py
  浏览器打开 http://127.0.0.1:5000,上传 PDF、选模型、点生成
