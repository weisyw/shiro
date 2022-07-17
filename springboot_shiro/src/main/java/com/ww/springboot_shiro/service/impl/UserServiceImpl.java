package com.ww.springboot_shiro.service.impl;

import com.ww.springboot_shiro.mapper.UserMapper;
import com.ww.springboot_shiro.pojo.User;
import com.ww.springboot_shiro.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @Author: ww
 * @DateTime: 2022/7/17 13:48
 * @Description: This is description of class
 */

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public User queryUserByName(String name) {
        User user = userMapper.queryUserByName(name);
        return user;
    }
}
