#include "payment_module.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <random>
#include <regex>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <jsoncpp/json/json.h>  // 使用jsoncpp库
#include <tinyxml2.h>   // 使用tinyxml2库

// 通用HTTP请求函数（使用cURL）
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb;
    userp->append((char*)contents, totalSize);
    return totalSize;
}

std::string http_request(const std::string& url, const std::string& data, bool is_post = true, bool verify_ssl = true) {
    CURL* curl;
    CURLcode res;
    std::string response;

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L); // 30秒超时
        
        // 启用SSL验证
        if(verify_ssl) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 启用SSL验证
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L); // 验证主机名
            // 可选：设置CA证书路径
            // curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/cacert.pem");
        } else {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        }

        if(is_post) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        }

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            if (res == CURLE_SSL_CONNECT_ERROR) {
                response = "SSL connection error: " + std::string(curl_easy_strerror(res));
            } else {
                response = "HTTP request failed: " + std::string(curl_easy_strerror(res));
            }
        }
        curl_easy_cleanup(curl);
    }
    
    return response;
}

// 控制台日志实现
void ConsoleLogger::log(LogLevel level, const std::string& message) {
    std::string level_str;
    switch(level) {
        case LogLevel::DEBUG:   level_str = "[DEBUG]"; break;
        case LogLevel::INFO:    level_str = "[INFO ]"; break;
        case LogLevel::WARNING: level_str = "[WARN ]"; break;
        case LogLevel::ERROR:   level_str = "[ERROR]"; break;
    }
    
    std::cout << level_str << " " << message << std::endl;
}

// 生成随机字符串
std::string generate_nonce_str(int length = 32) {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charset.size() - 1);
    
    std::string result;
    for(int i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }
    return result;
}

// 时间戳
std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::to_string(std::chrono::duration_cast<std::chrono::seconds>(duration).count());
}

// URL编码
std::string url_encode(const std::string& str) {
    std::string encoded;
    for(unsigned char c : str) {
        if(isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded += c;
        } else {
            char buf[4];
            snprintf(buf, sizeof(buf), "%%%02X", c);
            encoded += buf;
        }
    }
    return encoded;
}

// 微信支付实现
WeChatPayment::WeChatPayment(const std::string& app_id, const std::string& mch_id, const std::string& api_key)
    : app_id_(app_id), mch_id_(mch_id), api_key_(api_key) {}

PaymentResponse WeChatPayment::process_payment(const PaymentRequest& request) {
    PaymentResponse response;
    
    // 输入验证
    if (!PaymentInterface::validate_amount(request.amount)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid amount";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid payment amount: " + std::to_string(request.amount));
        return response;
    }
    
    if (!PaymentInterface::validate_order_id(request.order_id)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid order ID";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid order ID: " + request.order_id);
        return response;
    }
    
    if (!PaymentInterface::validate_description(request.description)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid description";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid description: " + request.description);
        return response;
    }
    
    try {
        // 构建请求参数
        std::map<std::string, std::string> params;
        params["appid"] = app_id_;
        params["mch_id"] = mch_id_;
        params["nonce_str"] = generate_nonce_str();
        params["body"] = request.description;
        params["out_trade_no"] = request.order_id;
        params["total_fee"] = std::to_string(static_cast<int>(request.amount * 100)); // 转换为分
        params["spbill_create_ip"] = "127.0.0.1"; // 实际应用中应获取客户端IP
        params["notify_url"] = "http://yourdomain.com/wechat_notify"; // 实际通知地址
        params["trade_type"] = "NATIVE"; // 扫码支付
        
        // 添加额外参数
        for(const auto& pair : request.extra_params) {
            params[pair.first] = pair.second;
        }
        
        // 生成签名
        params["sign"] = generate_sign(params);
        
        // 构建XML请求
        std::string xml_request = build_xml_request(params);
        
        // 发送请求
        std::string url = wechat_api_url_ + "/pay/unifiedorder";
        std::string result = make_http_request(url, xml_request);
        
        // 解析响应
        std::map<std::string, std::string> result_map = parse_xml_response(result);
        
        if(result_map["return_code"] == "SUCCESS" && result_map["result_code"] == "SUCCESS") {
            response.result = PaymentResult::SUCCESS;
            response.transaction_id = result_map["transaction_id"];
            response.payment_url = result_map["code_url"]; // 扫码支付的二维码链接
            response.message = "支付请求成功";
            response.extra_data = result_map;
            if (logger_) logger_->log(LogLevel::INFO, "Payment request successful: " + request.order_id);
        } else {
            response.result = PaymentResult::FAILED;
            response.message = result_map["err_code_des"];
            if (logger_) logger_->log(LogLevel::ERROR, "Payment request failed: " + result_map["err_code_des"]);
        }
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
        if (logger_) logger_->log(LogLevel::ERROR, "Exception in process_payment: " + std::string(e.what()));
    }
    
    return response;
}

PaymentResponse WeChatPayment::query_payment_status(const std::string& transaction_id) {
    PaymentResponse response;
    
    if (!PaymentInterface::validate_order_id(transaction_id)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid transaction ID";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid transaction ID: " + transaction_id);
        return response;
    }
    
    try {
        std::map<std::string, std::string> params;
        params["appid"] = app_id_;
        params["mch_id"] = mch_id_;
        params["nonce_str"] = generate_nonce_str();
        params["transaction_id"] = transaction_id;
        
        params["sign"] = generate_sign(params);
        std::string xml_request = build_xml_request(params);
        
        std::string url = wechat_api_url_ + "/pay/orderquery";
        std::string result = make_http_request(url, xml_request);
        
        std::map<std::string, std::string> result_map = parse_xml_response(result);
        
        if(result_map["return_code"] == "SUCCESS") {
            if(result_map["trade_state"] == "SUCCESS") {
                response.result = PaymentResult::SUCCESS;
                response.message = "支付成功";
            } else if(result_map["trade_state"] == "REFUND") {
                response.result = PaymentResult::FAILED;
                response.message = "转入退款";
            } else if(result_map["trade_state"] == "NOTPAY") {
                response.result = PaymentResult::PENDING;
                response.message = "未支付";
            } else if(result_map["trade_state"] == "CLOSED") {
                response.result = PaymentResult::CANCELLED;
                response.message = "已关闭";
            } else {
                response.result = PaymentResult::PENDING;
                response.message = result_map["trade_state_desc"];
            }
            
            response.transaction_id = transaction_id;
            response.extra_data = result_map;
            if (logger_) logger_->log(LogLevel::INFO, "Query status for " + transaction_id + ": " + result_map["trade_state"]);
        } else {
            response.result = PaymentResult::FAILED;
            response.message = result_map["return_msg"];
            if (logger_) logger_->log(LogLevel::ERROR, "Query failed for " + transaction_id + ": " + result_map["return_msg"]);
        }
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
        if (logger_) logger_->log(LogLevel::ERROR, "Exception in query_payment_status: " + std::string(e.what()));
    }
    
    return response;
}

PaymentResponse WeChatPayment::refund_payment(const std::string& transaction_id, double amount) {
    PaymentResponse response;
    
    if (!PaymentInterface::validate_order_id(transaction_id)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid transaction ID";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid transaction ID: " + transaction_id);
        return response;
    }
    
    if (!PaymentInterface::validate_amount(amount)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid refund amount";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid refund amount: " + std::to_string(amount));
        return response;
    }
    
    try {
        std::map<std::string, std::string> params;
        params["appid"] = app_id_;
        params["mch_id"] = mch_id_;
        params["nonce_str"] = generate_nonce_str();
        params["transaction_id"] = transaction_id;
        params["out_refund_no"] = generate_nonce_str(32); // 退款单号
        params["total_fee"] = std::to_string(static_cast<int>(amount * 100));
        params["refund_fee"] = std::to_string(static_cast<int>(amount * 100));
        
        params["sign"] = generate_sign(params);
        std::string xml_request = build_xml_request(params);
        
        std::string url = wechat_api_url_ + "/secapi/pay/refund";
        std::string result = make_http_request(url, xml_request);
        
        std::map<std::string, std::string> result_map = parse_xml_response(result);
        
        if(result_map["return_code"] == "SUCCESS" && result_map["result_code"] == "SUCCESS") {
            response.result = PaymentResult::SUCCESS;
            response.message = "退款申请成功";
            response.transaction_id = transaction_id;
            if (logger_) logger_->log(LogLevel::INFO, "Refund successful for " + transaction_id);
        } else {
            response.result = PaymentResult::FAILED;
            response.message = result_map["err_code_des"];
            if (logger_) logger_->log(LogLevel::ERROR, "Refund failed for " + transaction_id + ": " + result_map["err_code_des"]);
        }
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
        if (logger_) logger_->log(LogLevel::ERROR, "Exception in refund_payment: " + std::string(e.what()));
    }
    
    return response;
}

std::string WeChatPayment::generate_sign(const std::map<std::string, std::string>& params) {
    std::string str = "";
    bool first = true;
    
    for(const auto& pair : params) {
        if(pair.first != "sign" && !pair.second.empty()) {  // 排除sign参数且不为空
            if(!first) str += "&";
            str += pair.first + "=" + pair.second;
            first = false;
        }
    }
    
    // 添加API密钥
    str += "&key=" + api_key_;
    
    // MD5加密
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)str.c_str(), str.length(), digest);
    
    std::stringstream ss;
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    
    std::string sign = ss.str();
    std::transform(sign.begin(), sign.end(), sign.begin(), ::toupper);
    
    return sign;
}

std::string WeChatPayment::build_xml_request(const std::map<std::string, std::string>& params) {
    std::string xml = "<xml>";
    for(const auto& pair : params) {
        xml += "<" + pair.first + ">" + pair.second + "</" + pair.first + ">";
    }
    xml += "</xml>";
    return xml;
}

std::map<std::string, std::string> WeChatPayment::parse_xml_response(const std::string& xml) {
    std::map<std::string, std::string> result;
    
    // 使用tinyxml2解析XML
    tinyxml2::XMLDocument doc;
    doc.Parse(xml.c_str());
    
    if(doc.ErrorID() == 0) {
        tinyxml2::XMLElement* root = doc.FirstChildElement();
        if(root) {
            for(tinyxml2::XMLElement* elem = root->FirstChildElement(); 
                elem != nullptr; 
                elem = elem->NextSiblingElement()) {
                result[elem->Name()] = elem->GetText() ? elem->GetText() : "";
            }
        }
    }
    
    return result;
}

std::string WeChatPayment::make_http_request(const std::string& url, const std::string& data) {
    return http_request(url, data, true, verify_ssl_);
}

// 支付宝支付实现
AlipayPayment::AlipayPayment(const std::string& app_id, const std::string& private_key, const std::string& public_key)
    : app_id_(app_id), private_key_(private_key), public_key_(public_key) {}

PaymentResponse AlipayPayment::process_payment(const PaymentRequest& request) {
    PaymentResponse response;
    
    // 输入验证
    if (!PaymentInterface::validate_amount(request.amount)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid amount";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid payment amount: " + std::to_string(request.amount));
        return response;
    }
    
    if (!PaymentInterface::validate_order_id(request.order_id)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid order ID";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid order ID: " + request.order_id);
        return response;
    }
    
    if (!PaymentInterface::validate_description(request.description)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid description";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid description: " + request.description);
        return response;
    }
    
    try {
        std::map<std::string, std::string> params;
        params["app_id"] = app_id_;
        params["method"] = "alipay.trade.page.pay";
        params["format"] = "JSON";
        params["charset"] = "utf-8";
        params["sign_type"] = "RSA2";
        params["timestamp"] = get_timestamp();
        params["version"] = "1.0";
        params["notify_url"] = "http://yourdomain.com/alipay_notify";
        params["return_url"] = "http://yourdomain.com/alipay_return";
        
        // 业务参数
        std::map<std::string, std::string> biz_params;
        biz_params["out_trade_no"] = request.order_id;
        biz_params["total_amount"] = std::to_string(request.amount);
        biz_params["subject"] = request.description;
        biz_params["product_code"] = "FAST_INSTANT_TRADE_PAY";
        
        // 添加额外参数
        for(const auto& pair : request.extra_params) {
            biz_params[pair.first] = pair.second;
        }
        
        Json::Value biz_content;
        for(const auto& pair : biz_params) {
            biz_content[pair.first] = pair.second;
        }
        
        Json::StreamWriterBuilder writer;
        std::string biz_content_str = Json::writeString(writer, biz_content);
        params["biz_content"] = biz_content_str;
        
        // 生成签名
        params["sign"] = generate_sign(params);
        
        // 构建请求参数
        std::string request_data = build_request_params(params);
        
        response.result = PaymentResult::SUCCESS;
        response.payment_url = alipay_gateway_url_ + "?" + request_data;
        response.message = "支付请求构建成功";
        response.extra_data["request_data"] = request_data;
        if (logger_) logger_->log(LogLevel::INFO, "Payment request built successfully: " + request.order_id);
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
        if (logger_) logger_->log(LogLevel::ERROR, "Exception in process_payment: " + std::string(e.what()));
    }
    
    return response;
}

PaymentResponse AlipayPayment::query_payment_status(const std::string& transaction_id) {
    PaymentResponse response;
    
    if (!PaymentInterface::validate_order_id(transaction_id)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid transaction ID";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid transaction ID: " + transaction_id);
        return response;
    }
    
    try {
        std::map<std::string, std::string> params;
        params["app_id"] = app_id_;
        params["method"] = "alipay.trade.query";
        params["format"] = "JSON";
        params["charset"] = "utf-8";
        params["sign_type"] = "RSA2";
        params["timestamp"] = get_timestamp();
        params["version"] = "1.0";
        
        Json::Value biz_content;
        biz_content["trade_no"] = transaction_id;
        Json::StreamWriterBuilder writer;
        std::string biz_content_str = Json::writeString(writer, biz_content);
        params["biz_content"] = biz_content_str;
        
        params["sign"] = generate_sign(params);
        std::string request_data = build_request_params(params);
        
        std::string result = make_http_request(alipay_gateway_url_, request_data);
        std::map<std::string, std::string> result_map = parse_json_response(result);
        
        if(result_map.count("alipay_trade_query_response")) {
            Json::Value response_json;
            Json::Reader reader;
            if(reader.parse(result_map["alipay_trade_query_response"], response_json)) {
                std::string trade_status = response_json.get("trade_status", "").asString();
                
                if(trade_status == "TRADE_SUCCESS") {
                    response.result = PaymentResult::SUCCESS;
                    response.message = "支付成功";
                } else if(trade_status == "TRADE_CLOSED") {
                    response.result = PaymentResult::CANCELLED;
                    response.message = "交易关闭";
                } else {
                    response.result = PaymentResult::PENDING;
                    response.message = "交易进行中: " + trade_status;
                }
                
                response.transaction_id = transaction_id;
                response.extra_data = result_map;
                if (logger_) logger_->log(LogLevel::INFO, "Query status for " + transaction_id + ": " + trade_status);
            } else {
                response.result = PaymentResult::FAILED;
                response.message = "解析响应失败";
                if (logger_) logger_->log(LogLevel::ERROR, "Failed to parse response for " + transaction_id);
            }
        } else {
            response.result = PaymentResult::FAILED;
            response.message = "响应格式错误";
            if (logger_) logger_->log(LogLevel::ERROR, "Invalid response format for " + transaction_id);
        }
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
        if (logger_) logger_->log(LogLevel::ERROR, "Exception in query_payment_status: " + std::string(e.what()));
    }
    
    return response;
}

PaymentResponse AlipayPayment::refund_payment(const std::string& transaction_id, double amount) {
    PaymentResponse response;
    
    if (!PaymentInterface::validate_order_id(transaction_id)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid transaction ID";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid transaction ID: " + transaction_id);
        return response;
    }
    
    if (!PaymentInterface::validate_amount(amount)) {
        response.result = PaymentResult::FAILED;
        response.message = "Invalid refund amount";
        if (logger_) logger_->log(LogLevel::ERROR, "Invalid refund amount: " + std::to_string(amount));
        return response;
    }
    
    try {
        std::map<std::string, std::string> params;
        params["app_id"] = app_id_;
        params["method"] = "alipay.trade.refund";
        params["format"] = "JSON";
        params["charset"] = "utf-8";
        params["sign_type"] = "RSA2";
        params["timestamp"] = get_timestamp();
        params["version"] = "1.0";
        
        Json::Value biz_content;
        biz_content["trade_no"] = transaction_id;
        biz_content["refund_amount"] = std::to_string(amount);
        Json::StreamWriterBuilder writer;
        std::string biz_content_str = Json::writeString(writer, biz_content);
        params["biz_content"] = biz_content_str;
        
        params["sign"] = generate_sign(params);
        std::string request_data = build_request_params(params);
        
        std::string result = make_http_request(alipay_gateway_url_, request_data);
        std::map<std::string, std::string> result_map = parse_json_response(result);
        
        if(result_map.count("alipay_trade_refund_response")) {
            Json::Value response_json;
            Json::Reader reader;
            if(reader.parse(result_map["alipay_trade_refund_response"], response_json)) {
                if(response_json.get("code", "").asString() == "10000") { // 成功码
                    response.result = PaymentResult::SUCCESS;
                    response.message = "退款申请成功";
                    response.transaction_id = transaction_id;
                    if (logger_) logger_->log(LogLevel::INFO, "Refund successful for " + transaction_id);
                } else {
                    response.result = PaymentResult::FAILED;
                    response.message = response_json.get("sub_msg", "退款失败").asString();
                    if (logger_) logger_->log(LogLevel::ERROR, "Refund failed for " + transaction_id + ": " + response_json.get("sub_msg", "退款失败").asString());
                }
            } else {
                response.result = PaymentResult::FAILED;
                response.message = "解析响应失败";
                if (logger_) logger_->log(LogLevel::ERROR, "Failed to parse refund response for " + transaction_id);
            }
        } else {
            response.result = PaymentResult::FAILED;
            response.message = "响应格式错误";
            if (logger_) logger_->log(LogLevel::ERROR, "Invalid refund response format for " + transaction_id);
        }
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
        if (logger_) logger_->log(LogLevel::ERROR, "Exception in refund_payment: " + std::string(e.what()));
    }

    return response;
}

std::string AlipayPayment::generate_sign(const std::map<std::string, std::string>& params) {
    // 按字典序排序参数
    std::vector<std::pair<std::string, std::string>> sorted_params;
    for(const auto& pair : params) {
        if(pair.first != "sign" && !pair.second.empty()) {  // 排除sign参数且不为空
            sorted_params.push_back(pair);
        }
    }

    std::sort(sorted_params.begin(), sorted_params.end());

    std::string str = "";
    bool first = true;
    for(const auto& pair : sorted_params) {
        if(!first) str += "&";
        str += pair.first + "=" + pair.second;
        first = false;
    }

    // 使用RSA2(SHA256)签名
    try {
        KeyManager& km = KeyManager::instance();
        km.load_private_key(private_key_);
        return km.rsa_sign(str, "RSA2");
    } catch(const std::exception& e) {
        if (logger_) logger_->log(LogLevel::ERROR, "RSA signing failed: " + std::string(e.what()));
        // 如果RSA签名失败，返回错误
        throw e;
    }
}

std::string AlipayPayment::build_request_params(const std::map<std::string, std::string>& params) {
    std::string result = "";
    bool first = true;

    for(const auto& pair : params) {
        if(!first) result += "&";
        result += url_encode(pair.first) + "=" + url_encode(pair.second);
        first = false;
    }

    return result;
}

std::map<std::string, std::string> AlipayPayment::parse_json_response(const std::string& json) {
    std::map<std::string, std::string> result;

    Json::Value root;
    Json::Reader reader;

    if(reader.parse(json, root)) {
        Json::Value::Members members = root.getMemberNames();
        for(const auto& member : members) {
            Json::StreamWriterBuilder writer;
            result[member] = Json::writeString(writer, root[member]);
        }
    }

    return result;
}

std::string AlipayPayment::make_http_request(const std::string& url, const std::string& data) {
    return http_request(url, data, false, verify_ssl_); // GET请求
}

// 密钥管理实现
KeyManager& KeyManager::instance() {
    static KeyManager instance;
    return instance;
}

bool KeyManager::load_private_key(const std::string& key_content) {
    std::lock_guard<std::mutex> lock(mutex_);
    private_key_ = key_content;
    return true;
}

bool KeyManager::load_public_key(const std::string& key_content) {
    std::lock_guard<std::mutex> lock(mutex_);
    public_key_ = key_content;
    return true;
}

bool KeyManager::load_private_key_from_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return false;
    }
    
    std::string content;
    file.seekg(0, std::ios::end);
    content.reserve(file.tellg());
    file.seekg(0, std::ios::beg);

    content.assign((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());
    file.close();
    
    return load_private_key(content);
}

bool KeyManager::load_public_key_from_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return false;
    }
    
    std::string content;
    file.seekg(0, std::ios::end);
    content.reserve(file.tellg());
    file.seekg(0, std::ios::beg);

    content.assign((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());
    file.close();
    
    return load_public_key(content);
}

std::string KeyManager::rsa_sign(const std::string& data, const std::string& algorithm) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if(private_key_.empty()) {
        throw std::runtime_error("Private key not loaded");
    }

    BIO* bio = BIO_new_mem_buf(private_key_.c_str(), -1);
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    EVP_PKEY* pkey = NULL;
    // 尝试读取PKCS8格式的私钥
    pkey = d2i_PKCS8PrivateKey_bio(bio, NULL, NULL, NULL);
    if (!pkey) {
        // 如果失败，尝试传统的PEM格式
        BIO_reset(bio);
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    }
    BIO_free(bio);

    if (!pkey) {
        throw std::runtime_error("Failed to load private key");
    }

    // 检查密钥类型
    int key_type = EVP_PKEY_base_id(pkey);
    if (key_type != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Invalid key type, RSA expected");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create signing context");
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize signing");
    }

    // 根据算法选择摘要类型
    const EVP_MD* md = NULL;
    if (algorithm == "RSA2" || algorithm == "SHA256") {
        md = EVP_sha256();
    } else {
        md = EVP_sha1();
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set signature algorithm");
    }

    // 设置RSA padding方案
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set RSA padding");
    }

    // 获取签名长度
    size_t sig_len = 0;
    if (EVP_PKEY_sign(ctx, NULL, &sig_len, (unsigned char*)data.c_str(), data.length()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get signature length");
    }

    // 创建签名缓冲区
    unsigned char* sig = (unsigned char*)OPENSSL_malloc(sig_len);
    if (!sig) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to allocate signature buffer");
    }

    // 执行签名
    int result = EVP_PKEY_sign(ctx, sig, &sig_len, (unsigned char*)data.c_str(), data.length());
    if (result <= 0) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::string error_msg = "Failed to sign data: ";
        error_msg += err_buf;
        OPENSSL_free(sig);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error(error_msg);
    }

    // 将签名转换为Base64
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, sig, sig_len);
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    std::string signature(bptr->data, bptr->length); // 保留完整的Base64编码（含换行符）
    
    // 移除换行符
    signature.erase(std::remove(signature.begin(), signature.end(), '\n'), signature.end());
    signature.erase(std::remove(signature.begin(), signature.end(), '\r'), signature.end());

    // 清理资源
    BIO_free_all(b64);
    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return signature;
}

bool KeyManager::rsa_verify(const std::string& data, const std::string& signature, const std::string& algorithm) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if(public_key_.empty()) {
        throw std::runtime_error("Public key not loaded");
    }

    // 将Base64签名解码
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(bmem, signature.c_str(), signature.length());
    BIO_flush(bmem);

    int decoded_len = BIO_pending(bmem);
    char* decoded_sig = (char*)OPENSSL_malloc(decoded_len);
    int bytes_read = BIO_read(b64, decoded_sig, decoded_len);
    
    BIO_free_all(b64);

    if (bytes_read <= 0) {
        OPENSSL_free(decoded_sig);
        throw std::runtime_error("Failed to decode signature");
    }

    // 加载公钥
    BIO* bio = BIO_new_mem_buf(public_key_.c_str(), -1);
    if (!bio) {
        OPENSSL_free(decoded_sig);
        throw std::runtime_error("Failed to create BIO for public key");
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        // 尝试作为证书加载
        BIO_reset(bio);
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }
    BIO_free(bio);

    if (!pkey) {
        OPENSSL_free(decoded_sig);
        throw std::runtime_error("Failed to load public key");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        OPENSSL_free(decoded_sig);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create verification context");
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        OPENSSL_free(decoded_sig);
        throw std::runtime_error("Failed to initialize verification");
    }

    // 根据算法选择摘要类型
    const EVP_MD* md = NULL;
    if (algorithm == "RSA2" || algorithm == "SHA256") {
        md = EVP_sha256();
    } else {
        md = EVP_sha1();
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        OPENSSL_free(decoded_sig);
        throw std::runtime_error("Failed to set signature algorithm");
    }

    int result = EVP_PKEY_verify(ctx, (unsigned char*)decoded_sig, bytes_read, 
                                (unsigned char*)data.c_str(), data.length());

    OPENSSL_free(decoded_sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result == 1;
}

bool KeyManager::generate_rsa_keypair(std::string& private_key, std::string& public_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 创建RSA密钥对
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!ctx) {
        throw std::runtime_error("Failed to create RSA context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize key generation");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set key size");
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate keypair");
    }

    EVP_PKEY_CTX_free(ctx);

    // 提取私钥
    BIO* priv_bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PKCS8PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(priv_bio);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write private key");
    }

    BUF_MEM* priv_buf;
    BIO_get_mem_ptr(priv_bio, &priv_buf);
    private_key.assign(priv_buf->data, priv_buf->length);
    BIO_free(priv_bio);

    // 提取公钥
    BIO* pub_bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(pub_bio, pkey)) {
        BIO_free(pub_bio);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write public key");
    }

    BUF_MEM* pub_buf;
    BIO_get_mem_ptr(pub_bio, &pub_buf);
    public_key.assign(pub_buf->data, pub_buf->length);
    BIO_free(pub_bio);

    EVP_PKEY_free(pkey);
    
    return true;
}

// 输入验证实现
bool PaymentInterface::validate_amount(double amount) {
    return amount > 0 && amount <= 99999999; // 最大金额限制
}

bool PaymentInterface::validate_order_id(const std::string& order_id) {
    if(order_id.empty() || order_id.length() > 64) {
        return false;
    }
    
    // 订单ID只能包含字母、数字、下划线和连字符
    std::regex pattern("^[a-zA-Z0-9_-]+$");
    return std::regex_match(order_id, pattern);
}

bool PaymentInterface::validate_user_id(const std::string& user_id) {
    if(user_id.empty() || user_id.length() > 64) {
        return false;
    }
    
    // 用户ID只能包含字母、数字、下划线和连字符
    std::regex pattern("^[a-zA-Z0-9_-]+$");
    return std::regex_match(user_id, pattern);
}

bool PaymentInterface::validate_description(const std::string& description) {
    if(description.empty() || description.length() > 128) {
        return false;
    }
    
    // 检查是否包含危险字符
    std::regex dangerous_chars(R"([<>"'&])");
    return !std::regex_search(description, dangerous_chars);
}

// 支付工厂实现
std::unique_ptr<PaymentInterface> PaymentFactory::create_payment_processor(
    PaymentType type, const std::string& app_id, const std::string& key1, const std::string& key2) {

    switch(type) {
        case PaymentType::WECHAT:
            return std::make_unique<WeChatPayment>(app_id, key1, key2);
        case PaymentType::ALIPAY:
            return std::make_unique<AlipayPayment>(app_id, key1, key2);
        default:
            return nullptr;
    }
}

// 支付服务实现
PaymentService::PaymentService() {}

PaymentResponse PaymentService::process_payment(const PaymentRequest& request) {
    std::unique_ptr<PaymentInterface> processor = nullptr;

    switch(request.payment_type) {
        case PaymentType::WECHAT:
            if(wechat_payment_) {
                return wechat_payment_->process_payment(request);
            } else {
                PaymentResponse response;
                response.result = PaymentResult::FAILED;
                response.message = "微信支付未配置";
                return response;
            }
        case PaymentType::ALIPAY:
            if(alipay_payment_) {
                return alipay_payment_->process_payment(request);
            } else {
                PaymentResponse response;
                response.result = PaymentResult::FAILED;
                response.message = "支付宝支付未配置";
                return response;
            }
        default:
            PaymentResponse response;
            response.result = PaymentResult::FAILED;
            response.message = "不支持的支付类型";
            return response;
    }
}

PaymentResponse PaymentService::query_payment_status(const std::string& transaction_id, PaymentType type) {
    switch(type) {
        case PaymentType::WECHAT:
            if(wechat_payment_) {
                return wechat_payment_->query_payment_status(transaction_id);
            } else {
                PaymentResponse response;
                response.result = PaymentResult::FAILED;
                response.message = "微信支付未配置";
                return response;
            }
        case PaymentType::ALIPAY:
            if(alipay_payment_) {
                return alipay_payment_->query_payment_status(transaction_id);
            } else {
                PaymentResponse response;
                response.result = PaymentResult::FAILED;
                response.message = "支付宝支付未配置";
                return response;
            }
        default:
            PaymentResponse response;
            response.result = PaymentResult::FAILED;
            response.message = "不支持的支付类型";
            return response;
    }
}

PaymentResponse PaymentService::refund_payment(const std::string& transaction_id, double amount, PaymentType type) {
    switch(type) {
        case PaymentType::WECHAT:
            if(wechat_payment_) {
                return wechat_payment_->refund_payment(transaction_id, amount);
            } else {
                PaymentResponse response;
                response.result = PaymentResult::FAILED;
                response.message = "微信支付未配置";
                return response;
            }
        case PaymentType::ALIPAY:
            if(alipay_payment_) {
                return alipay_payment_->refund_payment(transaction_id, amount);
            } else {
                PaymentResponse response;
                response.result = PaymentResult::FAILED;
                response.message = "支付宝支付未配置";
                return response;
            }
        default:
            PaymentResponse response;
            response.result = PaymentResult::FAILED;
            response.message = "不支持的支付类型";
            return response;
    }
}

void PaymentService::set_wechat_config(const std::string& app_id, const std::string& mch_id, const std::string& api_key) {
    wechat_payment_ = std::make_unique<WeChatPayment>(app_id, mch_id, api_key);
    if (logger_) {
        wechat_payment_->set_logger(logger_);
    }
}

void PaymentService::set_alipay_config(const std::string& app_id, const std::string& private_key, const std::string& public_key) {
    alipay_payment_ = std::make_unique<AlipayPayment>(app_id, private_key, public_key);
    if (logger_) {
        alipay_payment_->set_logger(logger_);
    }
}

void PaymentService::set_logger(std::shared_ptr<Logger> logger) {
    logger_ = logger;
    if (wechat_payment_) {
        wechat_payment_->set_logger(logger);
    }
    if (alipay_payment_) {
        alipay_payment_->set_logger(logger);
    }
}