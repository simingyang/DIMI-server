#include "payment_module.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <random>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <jsoncpp/json/json.h>  // 使用jsoncpp库
#include <tinyxml2.h>   // 使用tinyxml2库

// 通用HTTP请求函数（使用cURL）
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb;
    userp->append((char*)contents, totalSize);
    return totalSize;
}

std::string http_request(const std::string& url, const std::string& data, bool is_post = true) {
    CURL* curl;
    CURLcode res;
    std::string response;

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L); // 30秒超时
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // 禁用SSL验证，生产环境应启用
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        if(is_post) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        }

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    
    return response;
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
        } else {
            response.result = PaymentResult::FAILED;
            response.message = result_map["err_code_des"];
        }
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
    }
    
    return response;
}

PaymentResponse WeChatPayment::query_payment_status(const std::string& transaction_id) {
    PaymentResponse response;
    
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
        } else {
            response.result = PaymentResult::FAILED;
            response.message = result_map["return_msg"];
        }
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
    }
    
    return response;
}

PaymentResponse WeChatPayment::refund_payment(const std::string& transaction_id, double amount) {
    PaymentResponse response;
    
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
        } else {
            response.result = PaymentResult::FAILED;
            response.message = result_map["err_code_des"];
        }
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
    }
    
    return response;
}

std::string WeChatPayment::generate_sign(const std::map<std::string, std::string>& params) {
    std::string str = "";
    bool first = true;
    
    for(const auto& pair : params) {
        if(!first) str += "&";
        str += pair.first + "=" + pair.second;
        first = false;
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
    return http_request(url, data, true);
}

// 支付宝支付实现
AlipayPayment::AlipayPayment(const std::string& app_id, const std::string& private_key, const std::string& public_key)
    : app_id_(app_id), private_key_(private_key), public_key_(public_key) {}

PaymentResponse AlipayPayment::process_payment(const PaymentRequest& request) {
    PaymentResponse response;
    
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
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
    }
    
    return response;
}

PaymentResponse AlipayPayment::query_payment_status(const std::string& transaction_id) {
    PaymentResponse response;
    
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
            } else {
                response.result = PaymentResult::FAILED;
                response.message = "解析响应失败";
            }
        } else {
            response.result = PaymentResult::FAILED;
            response.message = "响应格式错误";
        }
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
    }
    
    return response;
}

PaymentResponse AlipayPayment::refund_payment(const std::string& transaction_id, double amount) {
    PaymentResponse response;
    
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
                } else {
                    response.result = PaymentResult::FAILED;
                    response.message = response_json.get("sub_msg", "退款失败").asString();
                }
            } else {
                response.result = PaymentResult::FAILED;
                response.message = "解析响应失败";
            }
        } else {
            response.result = PaymentResult::FAILED;
            response.message = "响应格式错误";
        }
    } catch(const std::exception& e) {
        response.result = PaymentResult::FAILED;
        response.message = std::string("Exception: ") + e.what();
    }
    
    return response;
}

std::string AlipayPayment::generate_sign(const std::map<std::string, std::string>& params) {
    // 按字典序排序参数
    std::vector<std::pair<std::string, std::string>> sorted_params;
    for(const auto& pair : params) {
        if(pair.first != "sign") {  // 排除sign参数
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
    // 这里是简化实现，实际应该使用完整的RSA签名
    // 在实际应用中，需要使用私钥进行签名
    return "SIGNATURE_PLACEHOLDER"; // 实际应用中应替换为真实的签名
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
    return http_request(url, data, false); // GET请求
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
}

void PaymentService::set_alipay_config(const std::string& app_id, const std::string& private_key, const std::string& public_key) {
    alipay_payment_ = std::make_unique<AlipayPayment>(app_id, private_key, public_key);
}