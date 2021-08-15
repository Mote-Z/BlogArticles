

Title = "CTF"
description = "CTF题目复现记录"
tags = ["CTF"]
publishtime = 2021-07-26T16:14:00
lastedittime = 2021-08-12T09:31:00
uuid = "835dee22-8fff-43c2-bd43-6ac8c1e45409"
-+_+-



- 【0CTF/TCTF 2021】

	- 1linephp
		- Part1: PHP_SESSION_UPLOAD_PROGRESS的利用
		- Part2: zip://xxx%23mads 绕过后缀限制
		- Part2: libzip解析zip文件是从后往前的（通过指定偏移绕过session文件开头的脏数据upload_progress_）
		> First, search for the MAGIC of EOCD at the end of the file, and then read CDH according to the EOCD offset , and finally read the compressed file data according to the offset in CDH


	- soracon
		- Part1：php solr扩展实现存在反序列化问题
		- Part2：php反序列化利用链寻找







- 【Plaid CTF 2020】

	- Mooz Chat
		- Part1: 命令注入、JWT泄露导致Token伪造
		- Part2：中间人攻击获取数据包、64 bit Diffie-Hellman （使用GFNS算法分解）
	> https://blog.wangtuntun.com/articles/60a7b714-e7ca-4252-94c4-e944b3a2d1b7


	- Catalog
		- User Activation v2
		- Scroll Text Fragments
		- Image and Iframe via Lazy Loading
	
	> https://blog.wangtuntun.com/articles/59eff919-16b0-4d3c-8797-d5f92c9046dc



- 【Def Con Qual 2020】

    - uploooadit
        -  gunicorn 与 haproxy 在 CL 与 TE 之间解析差异导致的 smuggling

    > https://blog.wangtuntun.com/articles/b21e18dd-0a44-4b99-81e1-ad9c76e4c43f#:~:text=uploooadit

    - Pooot
        - 黑盒测试
        - xss 对 chrome service worker 的利用
        - xss 对 chrome 9222 远程调试端口的利用

    > https://blog.wangtuntun.com/articles/b21e18dd-0a44-4b99-81e1-ad9c76e4c43f#:~:text=Pooot

    - Dogooos
    	- Python模板注入

    > https://blog.wangtuntun.com/articles/b21e18dd-0a44-4b99-81e1-ad9c76e4c43f#:~:text=Dogooos

    - OOOnline Course
    	- Sqli Injection
    	- linux proc

    > https://blog.wangtuntun.com/articles/b21e18dd-0a44-4b99-81e1-ad9c76e4c43f#:~:text=OOOnline%20Course

    


- 【Defenit CTF 2020】

	- Tar Analyzer
        - Zip Slip Vulnerability ( allowing attackers to write arbitrary files on system)
            - Soft link  lead to arbitrary file read
            - Race Conditions
            - YAML Deserialization Attack  in Python

	> https://blog.wangtuntun.com/articles/40df009c-c2d1-4494-8bad-140e1c589670#:~:text=Tar%20Analyzer

	- BabyJS
		- handlebars Server Side Template Injection

	> https://blog.wangtuntun.com/articles/40df009c-c2d1-4494-8bad-140e1c589670#:~:text=BabyJS

	- Adult-JS
		- Program Analysis
		- UNC,SMB and WebDav

	> https://blog.wangtuntun.com/articles/40df009c-c2d1-4494-8bad-140e1c589670#:~:text=Adult-JS

	- Fortune-Cookie
		- Inject object using signedCookie
		- Method Overwrite in MongoDB
		- Exploit in reset cycle

	> https://blog.wangtuntun.com/articles/40df009c-c2d1-4494-8bad-140e1c589670#:~:text=Fortune-Cookie

	- highlighter
		- Static-eval prototype pollution.
		- Chrome Extension's `file:///` support

	> https://blog.wangtuntun.com/articles/40df009c-c2d1-4494-8bad-140e1c589670#:~:text=highlighter
