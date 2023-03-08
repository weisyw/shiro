## 1、权限管理
### 1.1 什么是权限管理
基本上涉及到用户参与的系统都要进行权限管理，权限管理属于系统安全的范畴，权限管理实现对用户访问系统的控制，按照安全规则或安全策略控制用户可以访问而且只能访问自己被授权的资源。
权限管理包括用户身份认证和授权两部分，简称认证授权。对于需要访问控制的资源，用户首先需要经过身份认证，认证通过后用户具有该资源的访问权限方可访问。
### 1.2 身份认证
身份认证就是判断一个用户是否为合法用户的处理过程。最常用的简单身份认证方式就是系统通过核对用户输入的用户名和口令，看其是否与系统中存储的该用户的用户名口令一致来判断用户身份是否正确。对于采用指纹等系统，则出示指纹；对于硬件Key等刷卡系统，则需要刷卡。
### 1.3 授权
授权即访问控制，控制谁能访问哪些资源。主体进行身份认证后需要分配权限方可访问系统的资源，对于某些资源没有权限是无法访问的。

## 2、什么是Shiro
> **Apache Shiro™** is a powerful and easy-to-use Java security framework that performs authentication, authorization, cryptography, and session management. With Shiro’s easy-to-understand API, you can quickly and easily secure any application – from the smallest mobile applications to the largest web and enterprise applications.
> **‎Apache Shiro™‎**‎是一个功能强大且易于使用的Java安全框架，可以执行身份验证，授权，加密和会话管理。借助 Shiro 易于理解的 API，您可以快速轻松地保护任何应用程序 - 从最小的移动应用程序到最大的 Web 和企业应用程序。‎

:::tips
Shiro是Apache旗下的一个开源框架，它将软件系统的安全认证相关的功能抽取出来，实现用户身份认证、权限授权、加密、会话管理等功能，组成了一个通用的安全认证框架。
:::

## 3、Shiro核心架构
![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1657627663573-fff8b709-e769-4174-989a-f3afc847d3b2.png#clientId=uf38d7e08-16ea-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=902&id=udfcee4bd&margin=%5Bobject%20Object%5D&name=image.png&originHeight=902&originWidth=2706&originalType=binary&ratio=1&rotation=0&showTitle=false&size=482500&status=done&style=none&taskId=ud0b79991-7b01-45c4-8950-33e37d0dcc5&title=&width=2706)
### 3.1 Subject
Subject即主体，外部应用与subject进行交互，subject记录了当前操作用户，将用户的概念理解为当前操作的主体，可能是一个通过浏览器请求的用户，也可能是一个运行的程序。Subject在shiro中是一个接口，接口中定义了很多认证授相关的方法，外部程序通过subject进行认证授，而subject是通过SecurityManager安全管理器进行认证授权。
### 3.2 SecurityManager
SecurityManager即安全管理器，对全部的subject进行安全管理，它是shiro的核心，负责对所有的subject进行安全管理。通过SecurityManager可以完成subject的认证、授权等，实质上SecurityManager是通过Authenticator进行认证，通过Authorizer进行授权，通过SessionManager进行会话管理等。
SecurityManager是一个接口，继承了Authenticator, Authorizer, SessionManager这三个接口。
### 3.3 Authenticator
Authenticator即认证器，对用户身份进行认证，Authenticator是一个接口，shiro提供ModularRealmAuthenticator实现类，通过ModularRealmAuthenticator基本上可以满足大多数需求，也可以自定义认证器。
### 3.4 Authorizer
Authorizer即授权器，用户通过认证器认证通过，在访问功能时需要通过授权器判断用户是否有此功能的操作权限。
### 3.5 Realm
Realm即领域，相当于datasource数据源，securityManager进行安全认证需要通过Realm获取用户权限数据，比如：如果用户身份数据在数据库那么realm就需要从数据库获取用户身份信息。
> 注意：不要把realm理解成只是从数据源取数据，在realm中还有认证授权校验的相关的代码。

### 3.6 SessionManager
sessionManager即会话管理，shiro框架定义了一套会话管理，它不依赖web容器的session，所以shiro可以使用在非web应用上，也可以将分布式应用的会话集中在一点管理，此特性可使它实现单点登录。
### 3.7 SessionDAO
SessionDAO即会话dao，是对session会话操作的一套接口，比如要将session存储到数据库，可以通过jdbc将会话存储到数据库。
### 3.8 CacheManager
CacheManager即缓存管理，将用户权限数据存储在缓存，这样可以提高性能。
### 3.9 Cryptography
Cryptography即密码管理，shiro提供了一套加密/解密的组件，方便开发。比如提供常用的散列、加/解密等功能。

## 4、Shiro中的认证
### 4.1 认证
身份认证，就是判断一个用户是否为合法用户的处理过程。最常用的简单身份认证方式是系统通过核对用户输入的用户名和口令，看其是否与系统中存储的该用户的用户名和口令一致，来判断用户身份是否正确。
### 4.2 认证中的关键对象

- **Subject(主体)**：访问系统的用户，主体可以是用户、程序等，进行认证的都称为主体；
- **Principal(身份信息)**：是主体（subject）进行身份认证的标识，标识必须具有唯一性，如用户名、手机号、邮箱地址等，一个主体可以有多个身份，但是必须有一个主身份（Primary Principal）；
- **Credential(凭证信息)**：是只有主体自己知道的安全信息，如密码、证书等。
### 4.3 认证流程
![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1657628847683-c05594f3-68ec-49b2-b623-bd12a3a6d1e5.png#clientId=u346db031-fc0c-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=197&id=u72c32c28&margin=%5Bobject%20Object%5D&name=image.png&originHeight=197&originWidth=785&originalType=binary&ratio=1&rotation=0&showTitle=false&size=8617&status=done&style=none&taskId=ub7df778e-873f-464b-944e-a4b84a6e818&title=&width=785)
### 4.4 认证开发

1. 引入依赖
```xml
<dependency>
  <groupId>org.apache.shiro</groupId>
  <artifactId>shiro-core</artifactId>
  <version>1.5.3</version>
</dependency>
```

2. 创建Shiro配置文件并输入以下配置信息
```properties
[users]
zhangsan=123
lisi=456
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1657629707022-31f565fe-63d7-4329-b4a6-40d05c33dd2a.png#clientId=u346db031-fc0c-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=218&id=ud01505a0&margin=%5Bobject%20Object%5D&name=image.png&originHeight=218&originWidth=294&originalType=binary&ratio=1&rotation=0&showTitle=false&size=7027&status=done&style=none&taskId=ub9bfcfba-9cd5-40b4-b74f-dda06b1fa94&title=&width=294)

3. 编写程序
```java
package com.ww.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;

public class TestAuthenticator {
    public static void main(String[] args) {
        // 1.创建安全管理器对象
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        // 2.给安全管理器设置realm
        securityManager.setRealm(new IniRealm("classpath:shiro.ini"));
        // 3.SecurityUtils 给全局工具类设置安全管理器
        SecurityUtils.setSecurityManager(securityManager);
        // 4.关键对象 subject
        Subject subject = SecurityUtils.getSubject();
        // 5.创建令牌
        UsernamePasswordToken token = new UsernamePasswordToken("zhangsan","123");
        // 6.认证
        try {
            System.out.println("认证状态：" + subject.isAuthenticated());
            subject.login(token);
            System.out.println("认证状态：" + subject.isAuthenticated());
        } catch (UnknownAccountException e) {
            e.printStackTrace();
            System.out.println("认证失败，用户名错误");
        } catch (IncorrectCredentialsException e) {
            e.printStackTrace();
            System.out.println("认证失败，密码错误");
        }
    }
}
```
### 4.5 自定义Realm
上边的程序使用的是Shiro自带的IniRealm，IniRealm从ini配置文件中读取用户的信息，大部分情况下需要从系统的数据库中读取用户信息，所以需要自定义realm。
#### 4.5.1 Shiro提供的Realm
![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1657803642712-a8a47051-0260-48a4-9052-30242532aeba.png#clientId=ua7353536-7149-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=1462&id=u723a1c91&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1462&originWidth=3176&originalType=binary&ratio=1&rotation=0&showTitle=false&size=119731&status=done&style=none&taskId=u8fb161ef-cf2e-4a18-abf9-5b8fdb877f4&title=&width=3176)
#### 4.5.2 根据认证源码认证使用的是SimpleAccountRealm
![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1657803681078-f6ba69b4-a83f-45fc-9706-18b058b37bf0.png#clientId=ua7353536-7149-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=976&id=u0acd95cc&margin=%5Bobject%20Object%5D&name=image.png&originHeight=976&originWidth=2768&originalType=binary&ratio=1&rotation=0&showTitle=false&size=61494&status=done&style=none&taskId=ue31aa4fd-197c-4247-ac2b-32d6a2413ee&title=&width=2768)
SimpleAccountRealm的部分源码中有两个方法一个是认证，一个是授权。
```java
public class SimpleAccountRealm extends AuthorizingRealm {
		//.......省略
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        SimpleAccount account = getUser(upToken.getUsername());
        if (account != null) {
            if (account.isLocked()) {
                throw new LockedAccountException("Account [" + account + "] is locked.");
            }
            if (account.isCredentialsExpired()) {
                String msg = "The credentials for account [" + account + "] are expired";
                throw new ExpiredCredentialsException(msg);
            }
        }
        return account;
    }

    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = getUsername(principals);
        USERS_LOCK.readLock().lock();
        try {
            return this.users.get(username);
        } finally {
            USERS_LOCK.readLock().unlock();
        }
    }
}
```
#### 4.5.3 自定义Realm
```java
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
```
#### 4.5.4 使用自定义Realm认证
```java
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
```
### 4.6 使用MD5和Salt
#### 4.6.1 自定义md5 + salt + hash
```java
public class CustomerMD5Realm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 获取身份信息
        String principal = (String) token.getPrincipal();
        // 模拟数据库
        if ("张三".equals(principal)){
            return new SimpleAuthenticationInfo(principal, "60cf52e7a2d5df5e91bc579b3b7cfc7c", ByteSource.Util.bytes("1qaz"),this.getName());
        }
        return null;
    }
}
```
#### 4.6.2 认证
```java
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
    }
}
```
## 5、Shiro中的授权
### 5.1 授权
授权，即访问控制，控制谁能访问哪些资源。主体进行身份认证后需要分配权限方可访问系统的资源，对于某些资源没有权限是无法访问的。
### 5.2 授权中的关键对象
**授权可简单理解为who对what(which)进行How操作：**

- Who：即主体（Subject），主体需要访问系统中的资源。
- What：即资源（Resource)，如系统菜单、页面、按钮、类方法、系统商品信息等。资源包括资源类型和资源实例，比如商品信息为资源类型，类型为t01的商品为资源实例，编号为001的商品信息也属于资源实例。
- How：权限/许可（Permission)，规定了主体对资源的操作许可，权限离开资源没有意义，如用户查询权限、用户添加权限、某个类方法的调用权限、编号为001用户的修改权限等，通过权限可知主体对哪些资源都有哪些操作许可。
### 5.3 授权流程
![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1657890320749-806c5a17-dbb1-44ef-9c8c-458c245502e9.png#clientId=u2fe7dba8-cd78-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=514&id=u9b21bdcc&margin=%5Bobject%20Object%5D&name=image.png&originHeight=514&originWidth=978&originalType=binary&ratio=1&rotation=0&showTitle=false&size=21662&status=done&style=none&taskId=u0d2927fe-951b-4dd1-908a-729ccd74b74&title=&width=978)
### 5.4 授权方式

1. 基于角色的访问控制

RBAC基于角色的访问控制（Role-Based Access Control）是以角色为中心进行访问控制。
```java
if(subject.hasRole("admin")){
   //操作什么资源
}
```

2. 基于资源的访问控制	

RBAC基于资源的访问控制（Resource-Based Access Control）是以资源为中心进行访问控制。
```java
if(subject.isPermission("user:update:01")){ //资源实例
  //对01用户进行修改
}
if(subject.isPermission("user:update:*")){  //资源类型
  //对01用户进行修改
}
```
### 5.5 权限字符串
权限字符串的规则是：资源标识符：操作：资源实例标识符，意思是对哪个资源的哪个实例具有什么操作，“:”是资源/操作/实例的分割符，权限字符串也可以使用*通配符。
例子：

- 用户创建权限：user:create，或user:create:*
- 用户修改实例001的权限：user:update:001
- 用户实例001的所有权限：user:*:001
### 5.6 Shiro中授权编程实现方式

- 编程式
```java
Subject subject = SecurityUtils.getSubject();
if(subject.hasRole(“admin”)) {
	//有权限
} else {
	//无权限
}
```

- 注解式
```java
@RequiresRoles("admin")
public void hello() {
	//有权限
}
```

- 标签式
```java
JSP/GSP 标签：在JSP/GSP 页面通过相应的标签完成：
<shiro:hasRole name="admin">
	<!— 有权限—>
</shiro:hasRole>
注意: Thymeleaf 中使用shiro需要额外集成!
```
### 5.7 开发授权
#### 5.7.1 realm的实现
```java
public class CustomerMD5Realm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String primaryPrincipal = (String) principals.getPrimaryPrincipal();
        System.out.println("身份信息：" + primaryPrincipal);
        // 根据身份信息、用户名 获取当前用户的角色信息，以及权限信息
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        // 将数据库中查询的权限信息赋值给权限对象
        simpleAuthorizationInfo.addRole("admin");
        simpleAuthorizationInfo.addRole("user");
        simpleAuthorizationInfo.addStringPermission("user:*:01");
        simpleAuthorizationInfo.addStringPermission("product:*:*");
        
        return simpleAuthorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 获取身份信息
        String principal = (String) token.getPrincipal();
        // 模拟数据库
        if ("张三".equals(principal)){
            return new SimpleAuthenticationInfo(principal, "60cf52e7a2d5df5e91bc579b3b7cfc7c", ByteSource.Util.bytes("1qaz"),this.getName());
        }
        return null;
    }
}
```
#### 5.7.2 授权
```java
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
```
## 6、整合SpringBoot
### 6.1 环境搭建

1. 引入依赖
```xml
<dependency>
  <groupId>org.apache.shiro</groupId>
  <artifactId>shiro-spring</artifactId>
  <version>1.5.3</version>
</dependency>
```

2. 自定义Realm
```java
public class UserRealm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("授权。。。。。");
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("认证。。。。。");
        return null;
    }
}
```

3. Shiro配置Bean
```java
@Configuration
public class ShiroConfig {

    // ShiroFilterFactoryBean
    @Bean
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("getDefaultWebSecurityManager") DefaultWebSecurityManager defaultWebSecurityManager){
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        // 设置安全管理器
        bean.setSecurityManager(defaultWebSecurityManager);
        return bean;
    }


    // DefaultWebSecurityBean
    @Bean
    public DefaultWebSecurityManager getDefaultWebSecurityManager(@Qualifier("userRealm") UserRealm userRealm){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 关联UserRealm
        securityManager.setRealm(userRealm);
        return securityManager;
    }


    // 创建Realm
    @Bean
    public UserRealm userRealm(){
        return new UserRealm();
    }
}
```

4. 创建3个页面和thymeleaf
```xml
<dependency>
  <groupId>org.thymeleaf</groupId>
  <artifactId>thymeleaf-spring5</artifactId>
</dependency>

<dependency>
  <groupId>org.thymeleaf.extras</groupId>
  <artifactId>thymeleaf-extras-java8time</artifactId>
</dependency>
```
```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>index</title>
</head>
<body>
<h1>首页</h1>
<p th:text="${msg}"></p>

<a th:href="@{/user/add}">add</a> <br>
<a th:href="@{/user/update}">update</a> <br>

</body>
</html>
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1658030195418-de48d654-63cb-4e06-a67c-3f01ac0d91a7.png#clientId=u6f1019bc-2d62-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=499&id=u0ac16ad2&margin=%5Bobject%20Object%5D&name=image.png&originHeight=499&originWidth=382&originalType=binary&ratio=1&rotation=0&showTitle=false&size=16503&status=done&style=none&taskId=u2ec7ec3a-963a-4f31-b2e1-59877055d04&title=&width=382)
### 6.2 实现登录拦截
#### 6.2.1 常见过滤器
shiro提供和多个默认的过滤器，我们可以用这些过滤器来配置控制指定url的权限

| **配置缩写** | **对应的过滤器** | **功能** |
| --- | --- | --- |
| anon | AnonymousFilter | 指定url可以匿名访问 |
| authc | FormAuthenticationFilter | 指定url需要form表单登录，默认会从请求中获取username、password,rememberMe等参数并尝试登录，如果登录不了就会跳转到loginUrl配置的路径。我们也可以用这个过滤器做默认的登录逻辑，但是一般都是我们自己在控制器写登录逻辑的，自己写的话出错返回的信息都可以定制嘛。 |
| authcBasic | BasicHttpAuthenticationFilter | 指定url需要basic登录 |
| logout | LogoutFilter | 登出过滤器，配置指定url就可以实现退出功能，非常方便 |
| noSessionCreation | NoSessionCreationFilter | 禁止创建会话 |
| perms | PermissionsAuthorizationFilter | 需要指定权限才能访问 |
| port | PortFilter | 需要指定端口才能访问 |
| rest | HttpMethodPermissionFilter | 将http请求方法转化成相应的动词来构造一个权限字符串 |
| roles | RolesAuthorizationFilter | 需要指定角色才能访问 |
| ssl | SslFilter | 需要https请求才能访问 |
| user | UserFilter | 需要已登录或“记住我”的用户才能访问 |

#### 6.2.2 实现
在ShiroConfig里修改
```java
@Bean
public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("getDefaultWebSecurityManager") DefaultWebSecurityManager defaultWebSecurityManager){
    ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
    // 设置安全管理器
    bean.setSecurityManager(defaultWebSecurityManager);
    // 添加Shiro内置过滤器
    Map<String, String> filterMap = new LinkedHashMap<>();
    filterMap.put("/user/add","authc");
    filterMap.put("/user/update","authc");
    bean.setFilterChainDefinitionMap(filterMap);
    // 如果没有权限，跳转登录请求
    bean.setLoginUrl("/toLogin");
    return bean;
}

```
此时访问add和update页面都会跳转到login页面
### 6.3 实现用户认证
#### 6.3.1 使用自定义参数认证
```java
@RequestMapping("/login")
public String login(String username, String password, Model model){
    // 获取当前用户
    Subject subject = SecurityUtils.getSubject();
    // 封装用户的登录数据
    UsernamePasswordToken token = new UsernamePasswordToken(username, password);
    try {
        subject.login(token);
        System.out.println("认证通过");
        return "index";
    } catch (UnknownAccountException e) {
        model.addAttribute("msg", "用户名错误");
        return "login";
    } catch (IncorrectCredentialsException e) {
        model.addAttribute("msg", "密码错误");
        return "login";
    }
}
```
```java
@Override
protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    System.out.println("认证。。。。。");
    // 从数据库中获取用户名和密码。。
    String name = "admin";
    String password = "123456";
    UsernamePasswordToken userToken = (UsernamePasswordToken) token;
    if (!userToken.getUsername().equals(name)){
        // 抛出UnknownAccountException
        return null;
    }
    // 密码认证，shiro自己做
    return new SimpleAuthenticationInfo("",password,"");
}
```
#### 6.3.2 使用MyBatis

1. 引入数据库相关依赖
1. 配置数据源
1. 编写认证代码
```java
@Override
protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    // 从数据库中获取用户名和密码。。
    UsernamePasswordToken userToken = (UsernamePasswordToken) token;
    User user = userService.queryUserByName(userToken.getUsername());
    if (user == null){
        // 抛出UnknownAccountException
        return null;
    }
    // 密码认证，shiro自己做
    return new SimpleAuthenticationInfo("",user.getPassword(),"");
}
```
### 6.4 实现授权
```java
@Bean
public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("getDefaultWebSecurityManager") DefaultWebSecurityManager defaultWebSecurityManager){
    ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
    // 设置安全管理器
    bean.setSecurityManager(defaultWebSecurityManager);
    // 添加Shiro内置过滤器 拦截
    Map<String, String> filterMap = new LinkedHashMap<>();
    
    // 授权 拥有user:add才能访问add
    filterMap.put("/user/add","perms[user:add]");
    filterMap.put("/user/update","perms[user:update]");
    
    filterMap.put("/user/*","authc");
    bean.setFilterChainDefinitionMap(filterMap);
    // 如果没有权限，设置登录请求
    bean.setLoginUrl("/toLogin");
    // 未授权页面
    bean.setUnauthorizedUrl("/noAuth");
    return bean;
}
```
```java
public class UserRealm extends AuthorizingRealm {

    @Autowired
    private UserService userService;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("授权。。。。。");
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

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
        // 密码认证，shiro自己做
        return new SimpleAuthenticationInfo(user,user.getPassword(),"");
    }
}
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1658040774001-d3286ddc-8677-4c4a-8c6e-48c099c28eb1.png#clientId=ubc72812b-66ba-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=116&id=ucd29312c&margin=%5Bobject%20Object%5D&name=image.png&originHeight=116&originWidth=299&originalType=binary&ratio=1&rotation=0&showTitle=false&size=5404&status=done&style=none&taskId=u29d28ef2-7acf-4c6d-b478-bb209e194e9&title=&width=299)
## 7、整合Thymeleaf

1. 引入依赖
```xml
<dependency>
  <groupId>com.github.theborakompanioni</groupId>
  <artifactId>thymeleaf-extras-shiro</artifactId>
  <version>2.0.0</version>
</dependency>
```

2. 修改页面
```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org"
    xmlns:shiro=" http://www.thymeleaf.org/thymeleaf-extras-shiro">
<head>
    <meta charset="UTF-8">
    <title>index</title>
</head>
<body>
<h1>首页</h1>
<p th:text="${msg}"></p>
<p th:if="${session.loginUser == null}">
    <a th:href="@{/toLogin}">登录</a>
</p>

<div shiro:hasPermission="user:add">
    <a th:href="@{/user/add}">add</a>
</div>
<div shiro:hasPermission="user:update">
    <a th:href="@{/user/update}">update</a>
</div>

</body>
</html>
```
