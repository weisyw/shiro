package com.ww.springboot_shiro.mapper;

import com.ww.springboot_shiro.pojo.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;

/**
 * @Author: ww
 * @DateTime: 2022/7/17 13:44
 * @Description: This is description of class
 */

@Mapper
public interface UserMapper {

    public User queryUserByName(@Param("name") String name);
}
