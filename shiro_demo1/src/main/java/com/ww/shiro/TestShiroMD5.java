package com.ww.shiro;

import org.apache.shiro.crypto.hash.Md5Hash;

/**
 * @Author: ww
 * @DateTime: 2022/7/15 20:05
 * @Description: This is description of class
 */
public class TestShiroMD5 {
    public static void main(String[] args) {

        // 创建MD5算法
//        Md5Hash md5Hash = new Md5Hash();
//        md5Hash.setBytes("123".getBytes());
//        String s = md5Hash.toHex();
//        System.out.println(s);

        // 使用md5 要用构造方法
        Md5Hash md5Hash = new Md5Hash("123");
        System.out.println(md5Hash.toHex());

        // 使用Md5 + salt
        Md5Hash md5Hash1 = new Md5Hash("123", "1qaz");
        System.out.println(md5Hash1.toHex());

        // 使用Md5 + salt + hash散列
        Md5Hash md5Hash2 = new Md5Hash("123", "1qaz", 1024);
        System.out.println(md5Hash2);

    }
}
