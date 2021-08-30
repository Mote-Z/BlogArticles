

Title = "细说Java动态代理"
description = "Java"
tags = ["Web","Security"]
publishtime = 2021-08-27T00:15:00
lastedittime = 2021-08-28T17:03:00
uuid = "9f8d7e65-5313-4d20-9da4-1e5a10940c46"
-+_+-

# Introduction

> 💡 解释：代理是指对目标对象额外的访问方式，即通过代理对象访问目标对象。
>
> 作用：在不修改原目标对象的前提下，提供额外的功能操作，从而扩展目标对象的功能。



代理模式实际上是一种设计模式，其中通常涉及三类角色：

- Subject
- RealSubject
- Proxy

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210830002301.png)

Proxy和RealSubject必须实现同一个接口；

Proxy必须包含RealSubject；



如果**根据字节码的创建时机**来分类，可以分为静态代理和动态代理：

- 在**程序运行前（也就是编译完成后，但是还没运行）**已经存在代理类的**字节码文件（class）**，Proxy和RealSubject的关系在程序运行前就确定了。
- 在程序运行期间由**JVM**根据反射等机制**动态的生成类的字节码**，并加载到**JVM**中，所以在运行前并不存在代理类的字节码文件。

# 静态代理

静态代理在场景简单的情况下是比较好维护的，但是在复杂场景下容易出现以下问题：

1. Proxy需要与RealSubject实现一样的接口，所以会有如下情况：
	1. 用一个代理类实现多个接口，会导致**代理类臃肿**。
	2. 用多个代理类，每个Proxy代理一个RealSubject，导致**产生过多的Proxy**，一旦接口增加方法，RealSubject与Proxy都要维护，成本太高。

# 动态代理

JVM类加载主要有以下几个阶段：加载（Loading）、验证（Verification）、准备（Preparation）、解析（Resolution）、初始化（Initialization）、使用（Using）、卸载（Unloading）。

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210830004010.png)

其中**加载**阶段需要完成以下3件事情：

1. 通过一个类的全限定名（包名 + 类名）来获取定义此类的二进制字节流
2. 将这个字节流所代表的静态存储结构转化为方法区的运行时数据结构
3. 在内存中生成一个代表这个类的 `java.lang.Class` 对象，作为方法区这个类的各种数据访问入口

但是类加载中的第一步，如何获取指定类的二进制字节流，有很多方法，比如

- 从ZIP包获取，这是JAR、EAR、WAR等常见包的基础
- 从网络中获取，典型的应用是 Applet
- **运行时计算生成**，这种场景使用最多的是动态代理技术，在 `java.lang.reflect.Proxy` 类中，就是用了 `ProxyGenerator.generateProxyClass` 来为特定接口生成形式为 `*$Proxy` 的代理类的二进制字节流
- 由其它文件生成，典型应用是JSP，即由JSP文件生成对应的Class类（关于JSP的生命周期，之前在这个地方有个小Puzzle，比如用\u000d如果出现在Java的注释里，编译器编译时会视为换行，JSP是在首次访问的时候交由JSP引擎进行翻译和编译，所以这也解释了为啥这个Unicode换行的Trick可以被用作JSP Webshell里，而且大部分Webshell查杀是会跳过注释的。）
- 从数据库中获取

所以，动态代理简单来说就是  **加载二进制数据到内存**` —> `**映射成jvm能识别的结构**` —> `**在内存中生成class文件**

# JDK中的动态代理

以JDK为例，在`java.lang.reflect` 包中通过`java.lang.reflect.Proxy` 类和`java.lang.reflect.InvocationHandler` 接口提供了生成动态代理类并调用的能力。 

**java.lang.reflect.Proxy类**

`java.lang.reflect.Proxy` 类的作用主要是用来**动态创建一个代理对象类**，它提供了许多的方法，其中最重要的是`newProxyInstance ()`方法，该方法的作用是**得到一个动态代理对象**，函数签名如下

```java
/**
     * 创建动态代理类实例，也就是创建代理对象
     *
     * @param loader     指定动态代理类的类加载器
     * @param interfaces 指定动态代理类的类需要实现的接口数组
     * @param h          动态代理处理类
     * @return 返回动态代理生成的代理类实例
     * @throws IllegalArgumentException 不正确的参数异常
     */

public static Object newProxyInstance(ClassLoader loader, Class<?>[] interfaces,  InvocationHandler h)  throws IllegalArgumentException
```

`java.lang.reflect.Proxy#newProxyInstance`中比较关键的就是`getProxyClass0()`，通过`getProxyClass0()`得到Proxy的Class，这个Class是在内存中的，在创建Proxy对象时，通过反射机制获得这个类的构造方法，然后创建Proxy实例。



**java.lang.reflect.InvocationHandler接口**

`java.lang.reflect.InvocationHandler` 接口只有一个方法，`invoke()`，该方法表示Proxy要执行的功能代码。

每一个Proxy类都必须要实现`java.lang.reflect.InvocationHandler` 这个接口。

```java
Object invoke(Object proxy, Method method, Object[] args) throws Throwable
```

- proxy参数：jdk创建的代理对象，无需赋值；

- method参数：目标类中的方法；

- args参数：Method参数中，接收的参数；

使用过程如下：

1. 创建一个实现InvocationHandler接口的类。
2. Overwrite invoke方法。



**JDK实现动态代理的过程**

1. 创建Subject和RealSubject。
2. 创建实现了InvocationHandler接口的Proxy，Overwrite invoke方法实现代理与功能增强。
4. 使用Proxy类的`newProxyInstance`方法，来创建代理对象，代理对象来执行目标方法调用。

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210830012549.png)

**JDK优缺点**

- JDK提供的动态代理解决了静态代理中需要生成大量的代理类的局限；

- 实现简答，只需要实现InvocationHandler接口的类并Overwrite invoke方法，

- JDK是利用**反射**生成代理类 Proxyxx.class 代理类字节码，进而生成对象，使用**反射导致其效率不高**。

- JDK动态代理**只能代理实现了接口的类**

	> ❓点解JDK只可以代理实现了接口的类？
	>
	> 原因在于JDK实现动态代理的方式就系利用接口动态生成RealSubject的Class，而且**代理类本身已经extends了Proxy，而java是不允许多重继承的**，但是允许实现多个接口

# CGLIB代理

当要代理的类没有实现接口的时候肿么办捏？这时候可以使用CGLIB代理，可以为没有实现接口的类提供代理，对JDK的动态代理做了很好的补充。（CGLIB是基于继承实现的）

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210830095010.png)

**CGLIB 底层**：

CGLIB底层使用了*ASM*（一种通用*Java*字节码操作和分析框架，使用类似SAX的解析器来提高性能），借助于ASM框架修改现有的class文件或动态生成class文件的能力，转换字节码并生成新的类。

**CGLIB 原理**：

1. 动态生成一个要代理类的子类，子类重写要代理的类的所有不是final的方法。
2. 在子类中采用方法拦截的技术拦截所有父类方法的调用，顺势织入横切逻辑。

**CGLIB优缺点**：

优点：

1.代理的类无需实现接口；

2.执行速度相对JDK动态代理较高；

缺点：

1.字节码库需要进行更新以保证在新版java上能运行；

2.动态创建代理对象的代价相对JDK动态代理较高；

3.代理的对象不能是final关键字修饰的

