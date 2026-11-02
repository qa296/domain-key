<div align="center">

# domain-key


##### 用域名和种子**自动**生成高强度且**唯一**的密码。

</div>


## 工作原理

脚本将 **域名主体**、**密码种子** 和 **账号后缀** 经 PBKDF2 + HKDF 派生成 512bit 密钥流，再通过拒绝采样和 Fisher-Yates 洗牌，生成 12 位包含大小写字母、数字、特殊字符的密码。同一网站 + 同一种子 = 同一密码，无需记忆也无需存储。

## 安装

1. 安装 [Tampermonkey](https://www.tampermonkey.net/) 或 [Violentmonkey](https://violentmonkey.github.io/) 浏览器扩展
2. 点击 [安装链接](https://github.com/qa296/domain-key/raw/main/domain-key.user.js) 或手动将 `domain-key.user.js` 内容添加到脚本管理器
3. 启用脚本，访问任意网站即可使用

## 使用方法

### 基本用法

1. 访问任意网站的注册/登录页面
2. 聚焦密码输入框，右侧出现 🔑 按钮
3. 点击按钮 → 密码自动填入并复制到剪贴板

### 首次使用

点击 🔑 按钮后会弹出种子设置对话框，输入至少 6 个字符的密码种子。也可通过 Tampermonkey 菜单 → "设置密码种子" 随时修改。

### 账号后缀

**Shift + 点击** 🔑 按钮，弹出后缀输入框。为同一域名的不同账号添加修饰符（如 `work`、`personal`），脚本会生成不同密码。也可以用一个只有你自己知道的固定词作后缀，脚本不会记住它，每次需要重新输入。

## 贡献

欢迎提交 Issue 和 Pull Request。
