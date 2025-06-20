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

### HASH生产

```
java -jar QiyuesuoDecrypt.jar -hash xxxx
```