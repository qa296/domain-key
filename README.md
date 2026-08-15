<div align="center">

# domain-key


##### **Automatically** generate a [strong]() and **unique** password from domain + your seed.

</div>

[中文文档](README.zh-CN.md)

## How It Works

The script concatenates **main domain part** + **your secret seed**, hashes with SHA-384, then generates a 12-character password containing uppercase, lowercase, digits, and special characters using rejection sampling and Fisher-Yates shuffle. Same website + same seed = same password — no memorization or storage required.

## Installation

1. Install [Tampermonkey](https://www.tampermonkey.net/) or [Violentmonkey](https://violentmonkey.github.io/) browser extension
2. Click [install link](https://github.com/qa296/domain-key/raw/main/domain-key.user.js) or manually add `domain-key.user.js` content to your script manager
3. Enable the script and visit any website to start using

## Usage

### Basic Usage

1. Visit any website's registration/login page
2. Focus on a password input field — a 🔑 button appears on the right
3. Click the button → password is automatically filled and copied to clipboard

### First Time Use

Clicking the 🔑 button opens a seed setup dialog. Enter at least 6 characters for your secret seed. You can also modify it anytime via Tampermonkey menu → "设置密码种子" (Set Password Seed).

### Account Suffix

**Shift + click** the 🔑 button to open the suffix input dialog. Add modifiers (like `work`, `personal`) for different accounts on the same domain, and the script will generate different passwords.

## Contributing

Issues and Pull Requests are welcome.
