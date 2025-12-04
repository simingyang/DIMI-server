#ifndef PAYMENT_CONFIG_H
#define PAYMENT_CONFIG_H

// 支付模块配置文件
// 用于定义支付模块的各种配置参数

// 微信支付相关配置
#define WECHAT_API_URL "https://api.mch.weixin.qq.com"
#define WECHAT_PAY_UNIFIED_ORDER "/pay/unifiedorder"
#define WECHAT_PAY_ORDER_QUERY "/pay/orderquery"
#define WECHAT_PAY_REFUND "/secapi/pay/refund"

// 支付宝相关配置
#define ALIPAY_GATEWAY_URL "https://openapi.alipay.com/gateway.do"

// HTTP请求相关配置
#define HTTP_REQUEST_TIMEOUT 30L  // 30秒超时
#define HTTP_MAX_REDIRECTS 5

// 签名算法相关
#define SIGN_TYPE_MD5 "MD5"
#define SIGN_TYPE_HMAC_SHA256 "HMAC-SHA256"
#define SIGN_TYPE_RSA "RSA"
#define SIGN_TYPE_RSA2 "RSA2"

// 支付结果相关
#define MAX_RETRY_TIMES 3
#define QUERY_INTERVAL_MS 1000  // 查询间隔1秒

// 字符编码
#define CHARSET_UTF8 "utf-8"
#define CHARSET_GBK "gbk"

#endif // PAYMENT_CONFIG_H