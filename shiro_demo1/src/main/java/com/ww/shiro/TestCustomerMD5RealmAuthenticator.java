package com.ww.shiro;

import com.ww.shiro.realm.CustomerMD5Realm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;

import java.util.Arrays;

/**
 * @Author: ww
 * @DateTime: 2022/7/15 20:16
 * @Description: This is description of class
 */
public class TestCustomerMD5RealmAuthenticator {
    public static void main(String[] args) {
        // 1.创建安全管理器
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        // 2.注入realm
        CustomerMD5Realm realm = new CustomerMD5Realm();
        // 2.2 设置realm使用的hash凭证匹配器
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("md5");
        credentialsMatcher.setHashIterations(1024);
        realm.setCredentialsMatcher(credentialsMatcher);
        defaultSecurityManager.setRealm(realm);
        // 3.将安全管理器注入安全工具
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        // 4.获取subject
        Subject subject = SecurityUtils.getSubject();
        // 5.认证
        UsernamePasswordToken token = new UsernamePasswordToken("张三", "123");
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

        //认证通过
        if(subject.isAuthenticated()){
            //基于角色权限管理
            boolean admin = subject.hasRole("admin");
            System.out.println(admin);

            boolean user = subject.hasRole("user");
            System.out.println(user);

            // 基于多角色权限控制
            boolean roles = subject.hasAllRoles(Arrays.asList("admin", "user"));
            System.out.println(roles);

            // 是否具有其中一个角色
            boolean[] booleans = subject.hasRoles(Arrays.asList("admin", "user", "super"));
            for (boolean aBoolean : booleans) {
                System.out.println(aBoolean);
            }

            // 基于权限字符串的访问控制 资源标识符:操作:资源类型
            boolean permitted = subject.isPermitted("product:create:001");
            System.out.println(permitted);

            boolean permitted1 = subject.isPermitted("user:create:01");
            System.out.println(permitted1);
        }
    }
}
