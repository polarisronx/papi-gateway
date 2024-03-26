package com.polaris.papigateway;

import com.polaris.papiclientsdk.utils.SignUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static com.polaris.papigateway.constant.GatewayConstant.IP_WHITE_LIST;

/**
 * @Author polaris
 * @Create 2024-03-26 19:13
 * @Version 1.0
 * ClassName CustomGlobalFilter
 * Package com.polaris.papigateway
 * Description
 */
@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter (ServerWebExchange exchange, GatewayFilterChain chain){
        ServerHttpRequest req = exchange.getRequest();
        // 01 打印请求日志
        log.info("请求唯一标识："+req.getId());
        log.info("请求路径："+req.getPath().value());
        log.info("请求方法："+req.getMethod());
        log.info("请求参数："+req.getQueryParams());
        String sourceAddress = req.getLocalAddress().getHostString();
        log.info("请求来源地址："+sourceAddress);
        log.info("请求来源端口："+req.getRemoteAddress());
        // 获取响应对象
        ServerHttpResponse resp = exchange.getResponse();
        // 02 访问控制：黑白名单
        if (!IP_WHITE_LIST.contains(sourceAddress)){
            return handleReject(resp);
        }
        // 03 用户鉴权
        // 从请求头中获取 签名认证的参数 的值
        HttpHeaders headers = req.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String body = headers.getFirst("body");
        String timestamp = headers.getFirst("timestamp");
        String nonce = headers.getFirst("nonce");
        String sign = headers.getFirst("sign");
        // 进行 权限校验 的验证逻辑
        // 校验 accessKey
        if (!accessKey.equals("polaris")){// 实际上后端的 accessKey 要从数据库中查，这里图方便就直接写死了
            // 抛出运行时异常，表示权限不足
            return handleReject(resp);
        }
        // 校验随机数 nonce
        if (Long.parseLong(nonce) > 10000){
            return handleReject(resp);
        }
        // 校验时间戳 timestamp 与 当前时间的差距，超过5分钟说明过期
        if (Math.abs(System.currentTimeMillis()/1000 - Long.parseLong(timestamp)) > 5 * 60){
            return handleReject(resp);
        }
        // 校验签名 sign
        // 假设 secretKey 为 "polaris"， 这里只是简单示例，实际应用中需要从数据库中查
        String expectedSign = SignUtils.genSign(body,"abcdefgh");
        if (!sign.equals(expectedSign)){
            return handleReject(resp);
        }
        // 04 判断接口是否存在

        // 05 请求转发，调用接口
        Mono<Void> filter = chain.filter(exchange);
        // 06 记录响应日志
        HttpStatus code = resp.getStatusCode();
        log.info("响应: {}", code);
        if (code == HttpStatus.OK){
            // 07 调用成功，记录调用次数
        }else {
            // 08 调用失败，返回错误码
            log.info("调用失败");
            return handleError(resp);
        }
        return filter;
    }

    @Override
    public int getOrder (){
        return 0;
    }

    /*
     *
     * 处理拒绝的逻辑
     * @param null
     * @return
     * @author polaris
     * @create 2024/3/26
     **/
    public Mono<Void> handleReject(ServerHttpResponse response){
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    /*
     *
     * 处理错误的逻辑
     * @param null
     * @return
     * @author polaris
     * @create 2024/3/26
     **/
    public Mono<Void> handleError(ServerHttpResponse response){
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }
}

