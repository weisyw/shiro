package com.ww.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * @Author: ww
 * @DateTime: 2022/7/14 21:04
 * @Description: 自定义的Realm实现，将认证或授权的数据来源转为数据库
 */
public class CustomerRealm extends AuthorizingRealm {

    // 授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return null;
    }

    // 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 1.通过token获取用户名
        String principal = (String) token.getPrincipal();
        // 2.使用身份信息查询数据库
        // 模拟数据库
        if ("zhangsan".equals(principal)){
            /**
             * 参数1：正确的用户名
             * 参数2：正确的密码
             * 参数3：提供当前realm的名字
             */
            SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo("zhangsan","1233",this.getName());
            return simpleAuthenticationInfo;
        }
        return null;
    }
}
