package com.polaris.papigateway.utils;

import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.Arrays;
import java.util.List;

/**
 * @Author polaris
 * @Create 2024-03-26 19:23
 * @Version 1.0
 * ClassName utils
 * Package com.polaris.papigateway
 * Description
 */
public class GatewayUtils {
    public static final List<String> IP_WHITE_LIST= Arrays.asList("127.0.0.1");
    public static final String INTERFACE_HOST="http:localhost:8123";

    public static String getFullUrl(ServerHttpRequest request) {
//        // 获取请求协议
//        String protocol = request.getScheme();
//
//        // 获取服务器名称
//        String serverName = request.getServerName();
//
//        // 获取端口号
//        int port = request.getServerPort();
//
//        // 获取请求URI
//        String uri = request.getRequestURI();
//
//        // 获取查询参数
//        String query = request.getQueryString();
//
//        // 拼接完整的URL
//        StringBuffer url = new StringBuffer();
//        url.append(protocol).append("://").append(serverName);
//        if (port != 80 && port != 443) {
//            url.append(":").append(port);
//        }
//        url.append(uri);
//        if (query != null) {
//            url.append("?").append(query);
//        }
//
//        // 返回完整URL
//        return url.toString();
        return null;
    }



}
