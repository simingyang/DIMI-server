#ifndef PAYMENT_MODULE_H
#define PAYMENT_MODULE_H

#include <string>
#include <map>
#include <memory>
#include <vector>
#include <fstream>
#include <mutex>
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

// 日志级别枚举
enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

// 日志接口
class Logger {
public:
    virtual ~Logger() = default;
    virtual void log(LogLevel level, const std::string& message) = 0;
};

// 控制台日志实现
class ConsoleLogger : public Logger {
public:
    void log(LogLevel level, const std::string& message) override;
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
    
    // 设置日志器
    void set_logger(std::shared_ptr<Logger> logger) { logger_ = logger; }
    
    // 输入验证
    static bool validate_amount(double amount);
    static bool validate_order_id(const std::string& order_id);
    static bool validate_user_id(const std::string& user_id);
    static bool validate_description(const std::string& description);

protected:
    std::shared_ptr<Logger> logger_;
};

// 密钥管理类
class KeyManager {
public:
    static KeyManager& instance();
    
    // 加载密钥
    bool load_private_key(const std::string& key_content);
    bool load_public_key(const std::string& key_content);
    bool load_private_key_from_file(const std::string& file_path);
    bool load_public_key_from_file(const std::string& file_path);
    
    // 获取密钥
    std::string get_private_key() const { return private_key_; }
    std::string get_public_key() const { return public_key_; }
    
    // RSA签名
    std::string rsa_sign(const std::string& data, const std::string& algorithm = "RSA2");
    bool rsa_verify(const std::string& data, const std::string& signature, const std::string& algorithm = "RSA2");
    
    // 生成新的密钥对
    bool generate_rsa_keypair(std::string& private_key, std::string& public_key);

private:
    KeyManager() = default;
    ~KeyManager() = default;
    KeyManager(const KeyManager&) = delete;
    KeyManager& operator=(const KeyManager&) = delete;
    
    std::string private_key_;
    std::string public_key_;
    mutable std::mutex mutex_;
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
    bool verify_ssl_ = true; // 默认启用SSL验证
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
    bool verify_ssl_ = true; // 默认启用SSL验证
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
    
    // 设置日志器
    void set_logger(std::shared_ptr<Logger> logger);

private:
    std::unique_ptr<PaymentInterface> wechat_payment_;
    std::unique_ptr<PaymentInterface> alipay_payment_;
    std::shared_ptr<Logger> logger_;
};

#endif // PAYMENT_MODULE_H