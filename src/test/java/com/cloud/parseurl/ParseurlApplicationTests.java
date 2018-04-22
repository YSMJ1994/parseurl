package com.cloud.parseurl;

import org.apache.tomcat.util.codec.binary.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.SortedMap;
import java.util.TreeMap;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ParseurlApplicationTests {

	@Test
	public void contextLoads() {
		SortedMap<String, String> message=new TreeMap<String, String>();
		message.put("Action", "DescribeInstances");
		message.put("SecretId", "AKIDz8krbsJ5yKBZQpn74WFkmLPx3gnPhESA");
		message.put("Region", "ap-guangzhou");
		message.put("Timestamp", "1465185768");
		message.put("Nonce", "11886");
		message.put("SignatureMethod", "HmacSHA256");
		String res = getSignature(message);
		System.out.println(res.equals("0EEm/HtGRr/VJXTAD9tYMth1Bzm3lLHz5RCDv1GdM8s="));
		System.out.println(encoding(res).equals("0EEm%2FHtGRr%2FVJXTAD9tYMth1Bzm3lLHz5RCDv1GdM8s%3D"));
		//message.put("Signature", getSignature(message));
	}

	String encoding(String str) {
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

	private String getSignature(SortedMap<String, String> message) {
		message.put("InstanceIds.0", "ins-09dx96dg");
		StringBuilder sb = new StringBuilder();
		for (Object key : message.keySet()) {
			sb.append(key).append("=").append(message.get(key)).append("&");
		}
		StringBuilder resSb = new StringBuilder();
		resSb.append("GETcvm.api.qcloud.com/v2/index.php?");
		resSb.append(sb);
		String resString = resSb.toString();
		resString = resString.substring(0, resString.length() - 1);
		String result = sha256_HMAC(resString, "Gu5t9xGARNpq86cd98joQYCN3Cozk1qA");
		return result;
	}

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
}
