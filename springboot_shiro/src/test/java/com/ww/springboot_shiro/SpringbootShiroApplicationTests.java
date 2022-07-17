package com.ww.springboot_shiro;

import com.ww.springboot_shiro.pojo.User;
import com.ww.springboot_shiro.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SpringbootShiroApplicationTests {

    @Autowired
    private UserService userService;

    @Test
    void contextLoads() {
        User user = userService.queryUserByName("张三");
        System.out.println(user);
    }

}
