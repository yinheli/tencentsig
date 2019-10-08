# 腾讯登录服务（Tencent Login Service，TLS） userSig 生成

> 这是纯go实现的版本，官方提供的是 cgo 版本，部分用户可能在 mac 等系统上会遇到编译失败的问题，故实现了这个版本


支持的 curve 包括： prime256v1, secp256k1

> 之前腾讯云只支持 secp256k1，后来测试发现有 prime256v1 的密钥

具体使用请参考 `usersig_test.go`

## 参考资料

* https://cloud.tencent.com/document/product/269/1510
* http://bbs.qcloud.com/thread-21826-1-1.html

## 更新

官方更新了新的签名算法 v2 参考：
https://github.com/tencentyun/tls-sig-api-v2-golang/blob/master/tencentyun/TLSSigAPI.go
