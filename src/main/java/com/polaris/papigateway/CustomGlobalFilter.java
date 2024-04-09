package com.polaris.papigateway;


import cn.hutool.core.util.RandomUtil;
import com.polaris.common.entity.InterfaceInfo;
import com.polaris.common.entity.User;
import com.polaris.common.exception.ErrorCode;
import com.polaris.common.service.InnerInterfaceInfoService;
import com.polaris.common.service.InnerUserInterfaceInfoService;
import com.polaris.common.service.InnerUserService;
import com.polaris.papiclientsdk.common.enums.RequestMethodEnum;

import com.polaris.papiclientsdk.common.execption.PapiClientSDKException;
import com.polaris.papiclientsdk.common.model.AbstractClient;
import com.polaris.papiclientsdk.common.model.Credential;
import com.polaris.papiclientsdk.common.utils.SignUtils;
import com.polaris.papigateway.exception.BusinessException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.*;



/**
 * @author polaris
 * @create 2024-03-26 19:13
 * @version 1.0
 * ClassName CustomGlobalFilter
 * Package com.polaris.papigateway
 * Description 网关全局过滤器，负责用户鉴权、接口是否存在校验
 */
@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {
    public static final List<String> IP_WHITE_LIST= Arrays.asList("127.0.0.1");
    public static final String INTERFACE_HOST="http://localhost:8123";

    @DubboReference
    private InnerUserService innerUserService;
    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;
    @DubboReference
    private InnerUserInterfaceInfoService innerUserInterfaceInfoService;

    @Override
    public Mono<Void> filter (ServerWebExchange exchange, GatewayFilterChain chain){
        ServerHttpRequest req = exchange.getRequest();
        String sourceAddress = Objects.requireNonNull(req.getLocalAddress()).getHostString();
        String method = Objects.requireNonNull(req.getMethod()).toString();
        MultiValueMap<String, String> queryParams = req.getQueryParams();
        // 01 打印请求日志
        log.info("请求唯一标识："+req.getId());
        log.info("请求方法："+ method);
        log.info("请求参数："+ queryParams);
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
        String contentType;
        if(method.equals(RequestMethodEnum.POST.getMethod())) {
            contentType = headers.getFirst("Content-Type");
        }else {
            contentType="-";
        }
        String host = headers.getFirst("Host");
        String authorization = headers.getFirst("Authorization");
        String action = headers.getFirst("Action");
        String nonce = headers.getFirst("nonce");
        String accessKey = headers.getFirst("AccessKey");
        String timestamp = headers.getFirst("Timestamp");
        String apiVersion = headers.getFirst("ApiVersion");
        String sdkVersion = headers.getFirst("SdkVersion");
        String hashedRequestPayload = headers.getFirst("Content-SHA256");

        if (StringUtils.isAnyBlank(authorization, accessKey, timestamp, nonce, action)){
            throw new BusinessException(ErrorCode.FORBIDDEN_ERROR,"参数缺失");
        }
        // 进行 权限校验 的验证逻辑
        User invokeUser = null;
        try {
            // 调用内部服务，根据AK获取用户信息
            invokeUser = innerUserService.getInvokeUser(accessKey);
        } catch (Exception e) {
            // 捕获异常
            log.error("获取用户信息失败", e);
        }
        if (invokeUser == null){
            // 用户为空说明AK异常，没有访问权限
            throw new BusinessException(ErrorCode.FORBIDDEN_ERROR,"密钥ID不正确或账户不存在");
        }
        // 校验随机数 nonce
        // todo 集成Redis后修复
        assert nonce != null;
//        if (Long.parseLong(nonce) > 10000){
//            return handleReject(resp);
//        }
        // 校验时间戳 timestamp 与 当前时间的差距，超过5分钟说明过期
        assert timestamp != null;
        if (Math.abs(System.currentTimeMillis()/1000 - Long.parseLong(timestamp)) > 5 * 60){
            throw new BusinessException(ErrorCode.NOT_LOGIN_ERROR,"请求已过期,请登录后重试");
        }
        // 04 判断接口是否存在
        InterfaceInfo interfaceInfo = null;
        try {
            interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(action, method);

        } catch (Exception e) {
            // 捕获异常
            log.error("获取接口信息失败", e);
        }
        if (interfaceInfo == null){
            // 接口不存在则说明没有权限
            throw new BusinessException(ErrorCode.NOT_FOUND_ERROR,"接口不存在");
        }
        // 校验签名 sign
        String secretKey = invokeUser.getSecretKey();
        String endpoint = interfaceInfo.getEndpoint();
        log.info("请求路径："+ "http://"+endpoint+req.getPath().value());
        // 生成签名

        Map<String, String> canonicalHeaderMap = AbstractClient.getCanonicalHeader(method, timestamp, contentType, endpoint);
        String canonicalRequest = null;
        try {
            canonicalRequest = AbstractClient.getCanonicalRequest(method, req.getPath().value(), canonicalHeaderMap, hashedRequestPayload, toHashMap(queryParams));
        } catch (PapiClientSDKException e) {
            throw new BusinessException(ErrorCode.SYSTEM_ERROR,e.getMessage());
        }

        String expectedAuthorization = null;
        try {
            expectedAuthorization = SignUtils.getAuthorization("papi",timestamp,new Credential(accessKey,secretKey),canonicalRequest,canonicalHeaderMap.get("signedHeaders"));
        } catch (PapiClientSDKException e) {
            throw new BusinessException(ErrorCode.SYSTEM_ERROR,e.getMessage());
        }

        if (authorization==null||!authorization.equals(expectedAuthorization)){
            // 签名为空或与服务器生成的签名不一致则说明没有权限
            throw new BusinessException(ErrorCode.NO_AUTH_ERROR,"请求非法");
        }

        Long interfaceInfoId = interfaceInfo.getId();
        Long userId = invokeUser.getId();
        // 05 判断是否还有调用次数
        if(innerUserInterfaceInfoService.leftCount(interfaceInfoId,userId)<=0){
            throw new BusinessException(ErrorCode.NO_ACCESS_ERROR,"调用次数不足");
        }
        // 06 请求转发，调用接口
        return handleResponse(exchange, chain, interfaceInfoId, userId);
    }

    /*
     *  处理响应，装饰Response
     * @param null
     * @return
     * @author polaris
     * @create 2024/3/26
     **/
    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain,Long interfaceInfoId,Long userId){
        try {
            ServerHttpResponse originalResponse = exchange.getResponse();
            // 缓存数据的工厂
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            // 07 响应结束，拿到响应码
            HttpStatus statusCode = originalResponse.getStatusCode();
            if (statusCode == HttpStatus.OK) {
                // 装饰，增强能力
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                    // 等调用完转发的接口后才会执行
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("body instanceof Flux: {}", (body instanceof Flux));
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            // 往返回值里写数据
                            // 拼接字符串
                            return super.writeWith(
                                    fluxBody.map(dataBuffer -> {
                                        // 08 调用成功，接口调用次数 + 1 invokeCount
                                        try {
                                            innerUserInterfaceInfoService.invokeCount(interfaceInfoId, userId);
                                        } catch (Exception e) {
                                            log.error("invokeCount error", e);
                                        }
                                        byte[] content = new byte[dataBuffer.readableByteCount()];
                                        dataBuffer.read(content);
                                        DataBufferUtils.release(dataBuffer);//释放掉内存
                                        // 构建日志
                                        StringBuilder sb2 = new StringBuilder(200);
                                        List<Object> rspArgs = new ArrayList<>();
                                        rspArgs.add(originalResponse.getStatusCode());
                                        String data = new String(content, StandardCharsets.UTF_8); //data
                                        sb2.append(data);
                                        // 打印日志
                                        log.info("响应结果：" + data);
                                        return bufferFactory.wrap(content);
                                    }));
                        } else {
                            // 8. 调用失败，返回一个规范的错误码
                            log.error("<--- {} 响应code异常", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };
                // 设置 response 对象为装饰过的
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            return chain.filter(exchange); // 降级处理返回数据
        } catch (Exception e) {
            log.error("网关处理响应异常" + e);
            return chain.filter(exchange);
        }
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
    public HashMap<String,String> toHashMap(MultiValueMap<String,String> map){
        HashMap<String, String> hashMap = new HashMap<>();
        for(String key:map.keySet()){
            hashMap.put(key,map.get(key).get(0));
        }
        return hashMap;
    }
}

