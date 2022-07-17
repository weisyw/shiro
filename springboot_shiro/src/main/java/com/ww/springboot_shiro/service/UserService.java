package com.ww.springboot_shiro.service;

import com.ww.springboot_shiro.pojo.User;

/**
 * @Author: ww
 * @DateTime: 2022/7/17 13:47
 * @Description: This is description of class
 */
public interface UserService {
    public User queryUserByName(String name);

}
