package com.cloud.parseurl;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * 创建自: Sober 时间: 2018/4/17.
 */
@RestController
@RequestMapping(value = "/")
public class ParseUrlController {
    @RequestMapping(value = "/domainParse", method = {RequestMethod.POST})
    @ResponseBody
    public Object domainParse(HttpServletRequest request, @RequestParam Map<String, String> map) {
        return domainParseService(request, map);
    }

    private Object domainParseService(HttpServletRequest request, Map<String, String> map) {
        String clientIp = getIpAdrress(request);
        String secretId = map.get("secretId");
        String secretKey = map.get("secretKey");
        String recordId = map.get("recordId");
        String domain = map.get("domain");
        String subDomain = map.get("subDomain");
        String region = map.get("region");
        String recordType = map.get("recordType");
        String recordLine = map.get("recordLine");

        if(null == secretId || null == secretKey || "".equals(secretId.trim()) || "".equals(secretKey.trim())) {
            return "请传入秘钥";
        }
        if(null == recordId || "".equals(recordId.trim())) {
            return "请传入要修改的解析记录id";
        }
        if(null == domain || "".equals(domain.trim())) {
            return "请传入主域名";
        }
        if(null == region || "".equals(region.trim())) {
            return "请传入地区";
        }
        SortedMap<String, String> message = new TreeMap<>();
        message.put("Action", "RecordModify");
        message.put("Nonce", String.valueOf((int) (Math.random() * 1000)));
        message.put("Region", "ap-shanghai-1");
        message.put("SecretId", secretId);
        message.put("SignatureMethod", "HmacSHA256");
        message.put("Timestamp", String.valueOf(new Date().getTime() / 1000));
        message.put("domain", "soberz.cn");
        message.put("recordId", "355023229");
        message.put("subDomain", "@");
        message.put("recordType", "A");
        message.put("recordLine", "默认");
        message.put("value", clientIp);
        //message.put("Signature", encodeing(getSignature(message)));
        message.put("Signature", getSignature(message, secretKey));
        //String res = post("https://cns.api.qcloud.com/v2/index.php", message);
        String url = resolveUrl("https://cns.api.qcloud.com/v2/index.php", message);
        String res = get(url);
        System.out.println(res);
        JSONObject jsonObject = JSON.parseObject(res);
        return jsonObject;
    }

    private String resolveUrl(String s, SortedMap<String, String> params) {
        StringBuilder sb = new StringBuilder();
        sb.append(s).append("?");
        StringBuilder paraSb = new StringBuilder();
        for (Map.Entry<String, String> e : params.entrySet()) {
            paraSb.append(encodeing(e.getKey()));
            paraSb.append("=");
            paraSb.append(encodeing(e.getValue()));
            paraSb.append("&");
        }
        String paraString = paraSb.substring(0, paraSb.length() - 1);
        sb.append(paraString);
        return sb.toString();
    }

    public String get(String url) {
        BufferedReader in = null;
        try {
            URL realUrl = new URL(url);
            // 打开和URL之间的连接
            URLConnection connection = realUrl.openConnection();
            // 设置通用的请求属性
            connection.setRequestProperty("accept", "*/*");
            connection.setRequestProperty("connection", "Keep-Alive");
            connection.setRequestProperty("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            // 建立实际的连接
            connection.connect();
            // 定义 BufferedReader输入流来读取URL的响应
            in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuffer sb = new StringBuffer();
            String line;
            while ((line = in.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        // 使用finally块来关闭输入流
        finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return null;
    }

    private String post(String url, SortedMap<String, String> params) {
        URL u = null;
        HttpURLConnection con = null;
        // 构建请求参数
        StringBuffer sb = new StringBuffer();
        String sendData = "";
        if (params != null) {
            for (Map.Entry<String, String> e : params.entrySet()) {
                sb.append(e.getKey());
                sb.append("=");
                sb.append(e.getValue());
                sb.append("&");
            }
            sendData = sb.substring(0, sb.length() - 1);
        }
        System.out.println("send_url:" + url);
        System.out.println("send_data:" + sendData);
        // 尝试发送请求
        try {
            u = new URL(url);
            con = (HttpURLConnection) u.openConnection();
            //// POST 只能为大写，严格限制，post会不识别
            con.setRequestMethod("POST");
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setUseCaches(false);
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            OutputStreamWriter osw = new OutputStreamWriter(con.getOutputStream(), "UTF-8");
            osw.write(sendData);
            osw.flush();
            osw.close();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }

        // 读取返回内容
        StringBuffer buffer = new StringBuffer();
        try {
            //一定要有返回值，否则无法把请求发送给server端。
            BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), "UTF-8"));
            String temp;
            while ((temp = br.readLine()) != null) {
                buffer.append(temp);
                buffer.append("\n");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return buffer.toString();
    }

    private String getSignature(SortedMap<String, String> message, String secretKey) {
        StringBuilder sb = new StringBuilder();
        for (Object key : message.keySet()) {
            sb.append(key).append("=").append(message.get(key)).append("&");
        }
        String para = sb.substring(0, sb.length() - 1);
        StringBuilder resSb = new StringBuilder();
        resSb.append("GETcns.api.qcloud.com/v2/index.php?");
        resSb.append(para);
        //String resString = encodeing(resSb.toString());
        String resString = resSb.toString();
        String result = sha256_HMAC(resString, secretKey);
        return result;
    }

    private String getIpAdrress(HttpServletRequest request) {
        String realIp = request.getRemoteAddr();
        return realIp;
    }

    /**
     * sha256_HMAC加密
     *
     * @param message 消息
     * @param secret  秘钥
     * @return 加密后字符串
     */
    private static String sha256_HMAC(String message, String secret) {
        String hash = "";
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            byte[] bytes = sha256_HMAC.doFinal(message.getBytes());
            hash = Base64.encodeBase64String(bytes);
        } catch (Exception e) {
            System.out.println("Error HmacSHA256 ===========" + e.getMessage());
        }
        return hash;
    }

    String encodeing(String str) {
        try {
            String firstEncode = URLEncoder.encode(str, "UTF-8");
            firstEncode = firstEncode.replace("+", "%20");
            firstEncode = firstEncode.replace("*", "%2A");
            firstEncode = firstEncode.replace("~", "%7E");
            return firstEncode;
        } catch (UnsupportedEncodingException e) {
            return "";
        }
    }
}
