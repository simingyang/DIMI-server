#ifndef PAYMENT_MODULE_H
#define PAYMENT_MODULE_H

#include <string>
#include <map>
#include <memory>
#include "payment_config.h"

// 支付结果枚举
enum class PaymentResult {
    SUCCESS,
    FAILED,
    PENDING,
    CANCELLED
};

// 支付类型枚举
enum class PaymentType {
    WECHAT,
    ALIPAY
};

// 支付请求结构体
struct PaymentRequest {
    std::string order_id;
    double amount;
    std::string description;
    std::string user_id;
    PaymentType payment_type;
    std::map<std::string, std::string> extra_params;
};

// 支付响应结构体
struct PaymentResponse {
    PaymentResult result;
    std::string transaction_id;
    std::string payment_url;
    std::string message;
    std::map<std::string, std::string> extra_data;
};

// 抽象支付接口
class PaymentInterface {
public:
    virtual ~PaymentInterface() = default;
    virtual PaymentResponse process_payment(const PaymentRequest& request) = 0;
    virtual PaymentResponse query_payment_status(const std::string& transaction_id) = 0;
    virtual PaymentResponse refund_payment(const std::string& transaction_id, double amount) = 0;
};

// 微信支付实现
class WeChatPayment : public PaymentInterface {
public:
    WeChatPayment(const std::string& app_id, const std::string& mch_id, const std::string& api_key);
    PaymentResponse process_payment(const PaymentRequest& request) override;
    PaymentResponse query_payment_status(const std::string& transaction_id) override;
    PaymentResponse refund_payment(const std::string& transaction_id, double amount) override;

private:
    std::string app_id_;
    std::string mch_id_;
    std::string api_key_;
    std::string wechat_api_url_ = WECHAT_API_URL;
    
    std::string generate_sign(const std::map<std::string, std::string>& params);
    std::string build_xml_request(const std::map<std::string, std::string>& params);
    std::map<std::string, std::string> parse_xml_response(const std::string& xml);
    std::string make_http_request(const std::string& url, const std::string& data);
};

// 支付宝支付实现
class AlipayPayment : public PaymentInterface {
public:
    AlipayPayment(const std::string& app_id, const std::string& private_key, const std::string& public_key);
    PaymentResponse process_payment(const PaymentRequest& request) override;
    PaymentResponse query_payment_status(const std::string& transaction_id) override;
    PaymentResponse refund_payment(const std::string& transaction_id, double amount) override;

private:
    std::string app_id_;
    std::string private_key_;
    std::string public_key_;
    std::string alipay_gateway_url_ = ALIPAY_GATEWAY_URL;
    
    std::string generate_sign(const std::map<std::string, std::string>& params);
    std::string build_request_params(const std::map<std::string, std::string>& params);
    std::map<std::string, std::string> parse_json_response(const std::string& json);
    std::string make_http_request(const std::string& url, const std::string& data);
};

// 支付工厂类
class PaymentFactory {
public:
    static std::unique_ptr<PaymentInterface> create_payment_processor(PaymentType type, 
        const std::string& app_id, const std::string& key1, const std::string& key2 = "");
};

// 主支付服务类
class PaymentService {
public:
    PaymentService();
    PaymentResponse process_payment(const PaymentRequest& request);
    PaymentResponse query_payment_status(const std::string& transaction_id, PaymentType type);
    PaymentResponse refund_payment(const std::string& transaction_id, double amount, PaymentType type);
    
    void set_wechat_config(const std::string& app_id, const std::string& mch_id, const std::string& api_key);
    void set_alipay_config(const std::string& app_id, const std::string& private_key, const std::string& public_key);

private:
    std::unique_ptr<PaymentInterface> wechat_payment_;
    std::unique_ptr<PaymentInterface> alipay_payment_;
};

#endif // PAYMENT_MODULE_H