# Poc-Monitor
## 关于

1. 状态 `failing` 为短期内没有更新
2. 可从 [new.json](https://raw.githubusercontent.com/sari3l/CVE-Monitor/main/new.json) 文件获取最近一次`新增`的CVE项目信息
3. 可从 [update.json](https://raw.githubusercontent.com/sari3l/CVE-Monitor/main/update.json) 文件获取最近一次`更新`的CVE项目信息
4. 可从年限目录内`README.md`获取当年完整信息
5. 可从`dateLog`目录获取当天新增、更新cve内容

## 通知

1. `enableRelatedQuery`关闭下只关注最近更新的项目，开启下会关注同CVE下其他项目
2. 只有`新增`才会触发通知，具体逻辑可自行修改 
3. 修改`search.go`中通知函数更换通知渠道，具体可看[sari3l/notify](https://github.com/sari3l/notify)项目

## TODO

1. 飞书推送
2. 数据持久化
3. 数据展示（[威胁情报库](https://adminlove520.github.io/treat_v1.0.2/)）
## Ending

    东方隐侠·Anonymous
