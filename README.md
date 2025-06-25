# QiyuesuoDecrypt

该工具用于契约锁数据库配置文件、web端password参数、数据表中用户手机号等信息的解密,同时支持生成hash替换密码字段。

本项目仅作为研究和学习使用。

## 用法

### 数据库密码

```
java -jar QiyuesuoDecrypt.jar -decrypt -db QYS@yc/F50RL2hoG1ZXZsfwN+EOhyhXtzutn
```

### 用户信息

```
java -jar QiyuesuoDecrypt.jar -decrypt -user {cipher}xxxxxx -salt xxx
```
每个用户的salt都不一样，从数据库中获取。

### web端密码

```
java -jar QiyuesuoDecrypt.jar -decrypt -web {cipher}xxxxxx
```

### HASH生成

```
java -jar QiyuesuoDecrypt.jar -hash xxxx
```

## 注意事项

1. 在Windows中，可能因为存在特殊符号比如{}导致得不到正确的输入，可以使用双引号括起来。
2. Java 8u161以下的版本在不安装补丁的情况下不支持256位的AES密钥，建议使用更高版本的jdk运行程序。
3. Hash生成部分生成的是管理员密码hash，用户的mobilehash等信息直接用普通sha256即可。