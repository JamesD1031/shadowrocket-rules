# Shadowrocket 云端规则

公开的无凭据规则发布仓库。只包含域名/IP 分流规则、策略组名称、上游公开快照和维护代码；没有节点密码、订阅地址、CA 证书或本机完整配置。

## 安装与更新

固定模块地址：

```text
https://raw.githubusercontent.com/JamesD1031/shadowrocket-rules/main/release/routing.module
```

在小火箭「配置 → 模块」添加该地址并启用，在「设置 → 自动更新 → 模块」开启后台更新，间隔设为 1 天。具体后台执行时间由应用与系统决定，不能保证准点；手动更新模块也可立即刷新。

模块规则先于本地主配置匹配。本机需要已有配套的策略组；组名记录于 `config/module.json`。节点选择、前置代理、DNS 设置、MITM 证书与兜底策略继续由本地配置管理。它不是通用的完整配置订阅，不包含节点。

## 分类规则集

个人规则按「代理入口直连、个人站点直连、前置代理、GitHub/Copilot、Google AI/认证、Meta/Muse」生成 6 个包，另打包 Max 补充规则。保留原有上游远程规则集的匹配顺序与策略，为所有条目添加中文备注。

查看 [中文分类清单](release/分类清单.md) 或 [机器可读索引](release/catalog.json)。当前客户端的原生列表仍以 URL 为标题；中文备注不能替换客户端标题。

`release/rules/` 使用内容摘要命名，保留旧包以兼容缓存模块。生成器逐条验证展开后的顺序、策略及 no-resolve 等选项；打包不改变匹配行为。

## 云端维护

GitHub Actions 每 6 小时检查一次 `LOWERTOP/Shadowrocket` 的 `lazy_group.conf`，约北京时间 02:17、08:17、14:17、20:17。GitHub 可能延迟调度。也支持 Actions 页面手动 Run workflow。

发现新版本后下载固定提交，校验格式、策略名和维护测试，再直接提交更新 `release/routing.module`、分类索引和规则包，无需手动合并 PR。没有变化时通常不产生提交；失败时保留上一版模块，按 GitHub 的 Actions 通知设置提醒。

若连续 30 天没有提交，工作流会生成一次不改文件的保活提交，避免公开仓库因 [60 天无活动而暂停定时任务](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/disable-and-enable-workflows)。

自动发布只跟进 `[Rule]`。DNS、Hosts、重写、脚本、MITM 与新增策略组不自动应用到本机；未知规则类型或本机不存在的策略名会阻止发布，等待维护。旧上游快照按提交保存在 `upstream/history/`，可追溯和回滚。

## 个人规则来源

个人规则仍在私有维护仓库统一编辑，通过 `tools/publish_public.py` 明确的文件白名单同步到此仓库。此仓库的 Actions 自行读取公开上游，不需要访问私有仓库，也不需要个人访问令牌或跨仓库密钥。

维护者每次修改个人规则后将公开源文件推送到此仓库，随后云端自动校验并生成模块。不要将本机导出或凭据提交到此公开仓库。

上游来源：[LOWERTOP/Shadowrocket](https://github.com/LOWERTOP/Shadowrocket)。当前固定提交和 SHA-256 见 `upstream/source.json`。
