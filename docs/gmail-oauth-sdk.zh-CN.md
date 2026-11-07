# Gmail OAuth 与原生动作

本分支只有受保护的 Node 24 多租户服务。OAuth 配置、浏览器授权、精确连接选择和动作执行均经过现有后端及[私有协议](contracts/saas-runtime.openapi.yaml)；没有本地公开控制台、静态 runtime token、默认连接、直接 SDK/MCP 执行入口或明文密钥存储。回调必须使用受控的后端 HTTPS 地址，不能从调用者请求头推断。托管 Gmail 保留真实工作空间项目和授权来源，不会自动退回本地 OAuth。

完整的原生附件、MIME、草稿编辑、回复关联、ID 和最小权限规则保留在[英文 Gmail 指南](gmail-oauth-sdk.md)。关键约束：

- 附件只选一种内容来源：实际 `contentBase64` 或当前作用域中的 `file: { fileId }`。`filename`、`mimeType` 可覆盖元数据。内联图片使用裸 `contentId`，HTML 引用 `cid:<id>`。
- 省略 `attachments` 保留现有文件；空数组删除全部。省略正文保留原有纯文本/HTML，提供正文则替换；`isHtml` 需要替换正文。无法安全编辑的 MIME 结构拒绝修改，不会静默丢弃内容。
- 最多 100 个附件、25,000,000 字节解码附件及 35,000,000 字节完整 MIME。Gmail 自身限制仍适用。
- `replyToMessageId` 是真实 Gmail 消息 ID；附带 `threadId` 必须匹配。仅给线程 ID 时选择最近的非草稿消息。缺少可用 RFC `Message-ID` 的目标拒绝发送/创建回复。
- `draftId` 标识稳定草稿；编辑会改变草稿内消息 `messageId`；发送会删除草稿并返回已发送消息 ID。RFC `Message-ID` 邮件头不是 Gmail 消息 ID。
- 新邮件发送用 `gmail.send`；回复另需 `gmail.readonly`；普通草稿用 `gmail.compose`；回复草稿/更换回复目标另需读取权限。`gmail.modify` 覆盖这些流程。权限名前缀为 `https://www.googleapis.com/auth/`。
- 连接验证调用 `users.getProfile`；只有 `gmail.send` 不足，需要额外 `gmail.readonly`，或使用 `gmail.compose`/`gmail.modify`。更新实际 OAuth scopes 后重新授权同一账号。

动作参数与供应商 scopes 不会启用 OpenConnector 函数。后端先验证身份、业务规则和人类确认，连接器再检查当前函数规则与真实作用域连接。超时或丢失写入响应不等于操作失败，不应自动重复发送邮件。
