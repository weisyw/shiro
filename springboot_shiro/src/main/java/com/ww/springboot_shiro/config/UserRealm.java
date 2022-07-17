package com.ww.springboot_shiro.config;

import com.ww.springboot_shiro.pojo.User;
import com.ww.springboot_shiro.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @Author: ww
 * @DateTime: 2022/7/17 11:39
 * @Description: This is description of class
 */
public class UserRealm extends AuthorizingRealm {

    @Autowired
    private UserService userService;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("授权。。。。。");
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // info.addStringPermission("user:add");

        // 拿到当前登录对象
        Subject subject = SecurityUtils.getSubject();
        User current = (User) subject.getPrincipal();

        // 设置当前用户的权限
        info.addStringPermission(current.getPerms());

        return info;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("认证。。。。。");
        // 从数据库中获取用户名和密码。。
        UsernamePasswordToken userToken = (UsernamePasswordToken) token;
        User user = userService.queryUserByName(userToken.getUsername());
        if (user == null){
            // 抛出UnknownAccountException
            return null;
        }

        // 此处三行有问题 密码都没过就存session了

        // 密码认证，shiro自己做
        return new SimpleAuthenticationInfo(user,user.getPassword(),"");
    }
}
