# 生产部署说明

## 1. 上传项目
把本目录上传到服务器，例如 `/root/ios_rule_prod`。

## 2. 执行部署
```bash
cd /root/ios_rule_prod
bash deploy.sh
```

## 3. 修改环境变量
```bash
nano /opt/ios-rule/.env
```
必须修改：
- `ADMIN_TOKEN`
- `XUI_PASSWORD`
- `XUI_SOCKS_INBOUND_ID`
- `BASE_URL`
- `SOCKS_SERVER_HOST`
- `SOCKS_SERVER_PORT`

修改后重启：
```bash
systemctl restart ios-rule
systemctl status ios-rule --no-pager
```

## 4. 配置 Nginx
```bash
cp /opt/ios-rule/deploy/nginx-ios-rule.conf /etc/nginx/sites-available/ios-rule
ln -sf /etc/nginx/sites-available/ios-rule /etc/nginx/sites-enabled/ios-rule
nginx -t
systemctl reload nginx
```

## 5. 检查接口
```bash
curl http://127.0.0.1:8000/api/health
```
浏览器访问：
- 用户页：`http://服务器IP/`
- 管理后台：`http://服务器IP/admin`

## 6. 3x-ui 要求
在 3x-ui 中创建一个 `mixed` 入站，端口和 `.env` 的 `SOCKS_SERVER_PORT` 一致。把入站 ID 填到 `XUI_SOCKS_INBOUND_ID`。

## 7. 本版本新增
- `/api/check` 验证接口
- 后台每 60 秒自动扫描过期用户
- 到期、封禁、订阅拉取时会触发从 3x-ui 删除用户
- 数据库默认放到 `data/cardkey.db`
- 所有生产敏感配置改为 `.env`

## 8. 重要安全提醒
不要把 `.env`、`data/cardkey.db`、证书私钥、真实 Token 上传到公开仓库。
