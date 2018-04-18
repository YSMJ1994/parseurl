package com.cloud.parseurl;

import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

/**
 * 创建自: Sober 时间: 2018/4/17.
 */
@RestController
@RequestMapping(value = "/")
public class ParseUrlController {

    static String url = "https://cns.api.qcloud.com/v2/index.php?Action=RecordModify";

    @RequestMapping(value = "/parse", method = {RequestMethod.GET, RequestMethod.POST})
    @ResponseBody
    public String parseUrl(@RequestParam Map<String, String> map) {
        return resolveMap(map);
    }

    String resolveMap(Map<String, String> map) {
        Map<String, String> result = new HashMap<>();
        for (String key : map.keySet()) {
            result.put(encodeing(key), encodeing(map.get(key)));
        }

        return "111";
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
