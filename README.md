# 腾讯登录服务（Tencent Login Service，TLS） userSig 生成

支持的 curve 包括： prime256v1, secp256k1

> 之前腾讯云只支持 secp256k1，后来测试发现有 prime256v1 的密钥

具体使用请参考 `usersig_test.go`

## 参考资料

* https://cloud.tencent.com/document/product/269/1510
* http://bbs.qcloud.com/thread-21826-1-1.html