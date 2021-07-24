Title = "Review ——Cross-Origin State Inference (COSI) Attacks Leaking Web Site States through XS-Leaks "

description = "本文介绍了一种 Cross-Origin State Inference（COSI）的攻击思路，可以应用于去匿名化以及指纹识别等方面"

tags = ["论文"] 

publishtime = 2020-05-27T11:22:00
lastedittime = 2020-05-27T11:22:00
uuid = "e5300202-5b94-43ea-9de7-9feda2555a03"
-+_+-

> ​	在以往有关COSI攻击的研究中，通常只能考虑两种状态或者关注于 infer 的途径（XS-Leak，cross-site leak），然而现实中，需要推断的状态往往大于两种，因此，需要一种方法来对状态个数大于2的情形进行 infer。
>
> ​	以往的研究往往只关注单一一类浏览器，这样的结果不具有普适性，容易造成 false positive，还需要对不同的浏览器进行区分，来提高推断结果的准确度。
>
> ​	在以往的研究中，往往只关注单一一种 XS-Leak 的方法，要是结合起来，能做更多的 infer。
## 一：本文概要

​	针对上述背景，本文介绍了一种 Cross-Origin State Inference（COSI）的攻击方式（实际上是对以往的零散的攻击做了一个系统性总结）主要用于去匿名化方面，攻击者可以诱导受害者访问精心构造的web页面，该页面包含一系列可以进行判断的攻击向量组合（各种不同的XS-Leak方式），可以对受害者在目标网站上的状态（登录与否、身份权限等等）进行推测（类似于侧信道的方式）。在文中，作者介绍了 COSI attack class 的概念，对现有的 COSI 攻击实例进行分类，并发现一种新的攻击类别（基于 window.postMessage）。作者将他们的研究结果做成了工具（Basta-COSI，一个开源平台 ElasTest 的一部分），并对该工具进行实践，检验工具的效果。



## 二：相关问题

**什么是用户状态？**

​	用户状态是指，浏览器在访问网站的过程中标识浏览器的一些属性，比如是否登录，是否通过 SSO 登录，看下面的图，这个图列举了一些常见的 User State

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20200527114514.png)



**所谓的 infer 是指什么？**

​	不同角色的账户，或者不同状态下访问相同的URL，可能会出现不同的响应结果（后面称为 SD-URL ，state-dependent URL），这里就存在差异性，根据响应的差异性，我们可以推测出来，该账户所属的角色，这就是所谓的 infer 的过程😃，通过这些 infer 得到的 User State 可以进行用户画像、指纹识别等应用。



**怎么获取这些具有差异性表现的 URL （SD-URL）？**

​	首先，被攻击的网站需要允许创建不同类型的账户，使用一个浏览器Bot爬虫，并观察不同账号以及未登录状态下，同一 URL 是否具有不同的响应，如果有，则可以作为一个 SD-URL。



**怎么使得受害者的浏览器访问这些 SD-URL 并获得浏览器的响应呢？**

​	首先，配合XSS漏洞，或者邮件攻击等形式将受害者浏览器引导到我们精心构造的攻击页面（包含各种攻击向量组合），要获取受害者浏览器的响应状态需要结合一些技巧。在本文中，作者将这些技巧进行了分类，分为

```
EventsFired（EF，事件触发型）	
Object Properties（OP，对象属性型）	PostMessage（PM，PostMessage型）
CSSPropRead（CSS，CSS型）	JSError（JSE，基于JS错误型） JSObjectRead（JOR，基于JS对象型） 
CSPViolation（CSP，CSP型）	AppCacheError（ACE，基于App缓存型）	Timing（T，基于时间型）
```

​	这些都是前人研究出来的 XS-Leak 的方法，可以参考这个[repo](https://github.com/xsleaks/xsleaks)，由于受害者浏览器是从攻击者构造的攻击页面来访问 SD-URL 的，因此攻击者是可以获取到响应的，虽然由于同源策略（CSP）的保护，我们不能直接获取到内容，但是，获取到一些响应状态还是没有问题的。（这个方法对于赛棍们来说应该是很熟悉了😂）



**怎么对COSI的攻击分类并找出新的攻击向量的？**

​	主要是搜集以往的零零散散的不同 XS-Leaks 技巧，将它们适配成本文介绍的 COSI 模型，并且在测试环境中对这些 XS-Leaks 进行排列组合，具体的表可以从原文的 TABLE Ⅲ 中找到，在此不详细叙述



## 三：攻击过程

**攻击假设**

- 假设攻击者可以诱导受害者在它们的浏览器上加载攻击页面，并且在准备阶段，攻击者需要对各类账号进行测试

- 受害者：假设受害者运行着浏览器，并在目标网站上处于某种状态，比如登录中，使用同一个浏览器访问攻击者构造的攻击页面

- 目标网站：存在 SD-URL，存在同源策略保护的敏感信息，没有设置CORS



**准备阶段**

​	准备阶段主要完成 SD-URL 的搜寻、攻击向量的组合以及攻击页面的生成，通过浏览器爬虫等方法，获取到网站的URL集合，并使用不同账号以及未登录账户进行测试，寻找到 SD-URL以后（一个SD-URL其实也就对应了一个攻击向量），还要进行充分的测试（有些 SD-URL有多个状态），对这些攻击向量进行组合，以适应多值状态（>2）和不同浏览器架构，最后生成攻击页面。



**攻击阶段**

​	在攻击阶段就是，利用一些方法（XSS，或者钓鱼邮件等）来诱导受害者访问我们的攻击页面，攻击页面会自动完成用户状态的 infer。



## 四：BASTA-COSI

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20200527085231.png)

​	该工具的结构如上图所示，其中**输入**为：目标网站、状态脚本、浏览器类型，**输出**为攻击页面，经过三个**主要流程**：1、URL data collection 2、Attack Vector Identification  3、Attack Page Generation，其获得的中间变量在图中已经很清晰了。

​	**URL data collection  说明**

​	下图中 `api.php`这个URL就存在差异性，可以判断不同用户状态，`offline.php`可以判断Logged Out状态和其余两类状态，但另外两类并不能区分，需要结合其他攻击向量做更细粒度的判断，经过 URL data collection  以后，得到 SD-URL 集合以及相关的日志信息。

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20200527091408.png)

**Attack Vector Identification 说明**

​	Attack Vector Identification 主要是进行 SD-URL 的类别的判断，以便确认使用哪种判断方法，比如有些判断是可以直接根据响应状态判断的2xx，4xx等，但是有些判断是基于事件，或者基于JS的，这种需要对应的判断方法，经过 Attack Vector Identification 之后，得到识别好的攻击向量



**Attack Page Generation 说明**

​	攻击向量的选择过程

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20200527123832.png)

攻击向量选择，去除无用的攻击向量，减少无谓的尝试，提高效率，Score 模块来对对应的攻击向量组合进行评价





## 五：实验探究

**实验验证**

对四个开源应用（HotCRP，GitLab，GitHub Enterprise，OpenCart）以及58个在 Alexa 上排行前150的网站进行测试

**实验结果**



1. 对四个开源应用的测试

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20200527163209.png)

​	该表是 Basta-COSI 对四个开源应用的本地测试结果汇总，列出了每个主要步骤中的发现

- Data Collection阶段：输入的 state scripts 数量、爬取到URL的数量、识别为 SD-URL的数量

- Attack Vector Identification阶段：提取出的攻击向量的数量、这些攻击向量所覆盖的 state pairs 、 涉及到的 XS-Leaks 技巧的数量

- Attack Page Generation阶段：能直接识别的状态数量、部分识别的状态数量、在攻击页面中的最小，平均，最大攻击向量的数量
- 最后展示了受影响的浏览器种类以及攻击类型



2. 对Alexa上排行前150的部分应用进行测试

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20200527165938.png)

​	在排除了需要身份验证才能注册的网站以后，只剩下58个网站，可以看到几乎所有网站都能被 Surfing Attack 来进行登录状态检测



3. 各XS-Leak在各浏览器中所发现的各类漏洞的数量

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20200527170957.png)

其中，57%的网站能做到去匿名化的检测，45%的可达性检测



## 六：防御方法

1. 可以在Cookie中设置 SameSite 属性来防止浏览器跨域发送 cookies，这会阻止那些依靠返回cookie进行判断的漏洞
2. 使用session来替换cookie
3. [Cross-Origin-Resource-Policy](https://s0developer0mozilla0org.icopy.site/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy_(CORP)) 跨域资源策略是一个 HTTP 头，使网站和应用程序可以选择针对某些跨域请求（例如由诸如`<script>`和`<img>`类的元素发出的跨域请求）进行保护，以减轻诸如以及跨站点脚本包含攻击
4. [Fetch metadata](https://www.w3.org/TR/fetch-metadata/) 是Chrome中的一个特性，在发送出请求的时候，浏览器会增加一些额外的头比如 `Sec-Fetch-*`来描述这个请求的一些相关信息
5. [Cross-Origin-Opener-Policy](https://www.chromestatus.com/feature/5432089535053824) 能让你确保顶层 window 在其他上下文中是单独隔离的
6. 使用 Tor 浏览器
7. 对 SD-URL 进行修补



## 七：总结

目前已经被发现的XS-Leaks技巧如下图

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20200527172920.png)

本文的主要工作在于对零散的攻击资源进行了整合，形成了一套较为完备的体系，并应用在实际中，开发了工具进行验证



## 八：附录

https://medium.com/bugbountywriteup/cross-site-content-and-status-types-leakage-ef2dab0a492

https://sirdarckcat.blogspot.com/2019/03/http-cache-cross-site-leaks.html

https://portswigger.net/daily-swig/new-xs-leak-techniques-reveal-fresh-ways-to-expose-user-information

https://portswigger.net/research/xs-leak-leaking-ids-using-focus