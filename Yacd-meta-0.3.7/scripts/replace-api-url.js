#!/usr/bin/env node
/**
 * 构建前替换API URL脚本
 * 使用方法：
 * 1. 设置环境变量: export VITE_API_BASE_URL="http://your-server-ip:9090"
 * 2. 运行: node scripts/replace-api-url.js
 * 或直接: VITE_API_BASE_URL="http://your-server-ip:9090" npm run build
 */

const fs = require('fs');
const path = require('path');

// 从环境变量读取API URL，支持VITE_API_BASE_URL或API_BASE_URL
const apiUrl = process.env.VITE_API_BASE_URL || process.env.API_BASE_URL || 'http://127.0.0.1:9090';

console.log(`🔧 正在设置API URL: ${apiUrl}`);

const indexPath = path.join(__dirname, '../index.html');

if (!fs.existsSync(indexPath)) {
  console.error(`❌ 找不到文件: ${indexPath}`);
  process.exit(1);
}

let html = fs.readFileSync(indexPath, 'utf8');

// 替换 data-base-url 属性
const oldMatch = html.match(/data-base-url="([^"]*)"/);
if (oldMatch) {
  console.log(`📝 原API URL: ${oldMatch[1]}`);
}

html = html.replace(
  /data-base-url="[^"]*"/,
  `data-base-url="${apiUrl}"`
);

fs.writeFileSync(indexPath, html, 'utf8');
console.log(`✅ API URL 已设置为: ${apiUrl}`);

// 同时创建一个环境变量配置文件，供代码读取（如果需要）
const envConfig = {
  VITE_API_BASE_URL: apiUrl
};
fs.writeFileSync(
  path.join(__dirname, '../.env.local'),
  `VITE_API_BASE_URL=${apiUrl}\n`
);
console.log(`📁 已创建 .env.local 文件`);