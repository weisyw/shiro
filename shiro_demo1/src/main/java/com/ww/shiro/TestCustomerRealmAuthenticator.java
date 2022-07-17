package com.ww.shiro;

import com.ww.shiro.realm.CustomerRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;


/**
 * @Author: ww
 * @DateTime: 2022/7/14 21:07
 * @Description: 使用自定义realm
 */
public class TestCustomerRealmAuthenticator {
    public static void main(String[] args) {
        // 1.创建securityManager
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        // 2.设置自定义的realm
        defaultSecurityManager.setRealm(new CustomerRealm());
        // 3.将安全工具类设置安全管理器
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        // 4.通过安全工具类获取subject
        Subject subject = SecurityUtils.getSubject();
        // 5.创建token
        UsernamePasswordToken token = new UsernamePasswordToken("zhangsan", "123");
        try {
            subject.login(token);
            System.out.println("认证通过");
        } catch (UnknownAccountException e) {
            e.printStackTrace();
            System.out.println("认证失败，用户名错误");
        } catch (IncorrectCredentialsException e) {
            e.printStackTrace();
            System.out.println("认证失败，密码错误");
        }
    }
}
