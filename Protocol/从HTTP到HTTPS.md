

Title = "HTTPS原理探究"
description = "分析TLS1.2情况下的原理"
tags = ["Protocol","Security"]
publishtime = 2021-08-13T14:09:00
lastedittime = 2021-08-13T14:09:00
uuid = "ceabf2b9-4f60-4a8b-84ae-a88c3e0399ec"
-+_+-

# HTTPS

HTTPS是由HTTP进行通信，利用SSL/TLS建立安全信道，加密数据包

目前TLS有两个版本

| TLS版本 | 标准     | 状态     |
| ------- | -------- | -------- |
| TLS 1.1 | RFC 4346 | 已废弃   |
| TLS 1.2 | RFC 5246 | 广泛使用 |
| TLS 1.3 | RFC 8446 | 逐渐推广 |



## TLS Record Protocol

```c
struct {
    uint8 major;
    uint8 minor;
} ProtocolVersion;

enum {
    change_cipher_spec(20), alert(21), handshake(22),
    application_data(23), (255)
} ContentType;

struct {
    ContentType type;
    ProtocolVersion version;
    uint16 length;
    opaque fragment[TLSPlaintext.length];
} TLSPlaintext;
```





## Handshake Protocol

```c
enum {
    hello_request(0), client_hello(1), server_hello(2),
    certificate(11), server_key_exchange (12),
    certificate_request(13), server_hello_done(14),
    certificate_verify(15), client_key_exchange(16),
    finished(20), (255)
} HandshakeType;

struct {
    HandshakeType msg_type;    /* handshake type */
    uint24 length;             /* bytes in message */
    select (HandshakeType) {
        case hello_request:       HelloRequest;
        case client_hello:        ClientHello;
        case server_hello:        ServerHello;
        case certificate:         Certificate;
        case server_key_exchange: ServerKeyExchange;
        case certificate_request: CertificateRequest;
        case server_hello_done:   ServerHelloDone;
        case certificate_verify:  CertificateVerify;
        case client_key_exchange: ClientKeyExchange;
        case finished:            Finished;
    } body;
} Handshake;
```







## TLS 1.1握手

> TLS 1.1 已经废弃

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210813121021.png)



## TLS 1.2握手（非双向认证情况下）



> firefox抓TLS 1.2的包时需要导入master key 并且将about:config中的security.tls.version相关值修改为2



![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210813121512.png)



- Client Hello

	```c
	struct {
	    ProtocolVersion client_version; // 客户端期望交互的TLS版本号
	    Random random; // 包括一个32位的时间戳和28字节的随机数
	    SessionID session_id; // 不定长的id标识，一般情况下为空，在复用时使用减少协商交互次数
	    CipherSuite cipher_suites<2..2^16-2>; // 支持的套件列表
	    CompressionMethod compression_methods<1..2^8-1>; // 支持的压缩方法列表
	    // 扩展相关
	    select (extensions_present) {
	        case false:
	            struct {};
	        case true:
	            Extension extensions<0..2^16-1>;
	    };
	} ClientHello;
	
	struct {
	    uint32 gmt_unix_time;
	    opaque random_bytes[28];
	} Random;
	```

	

	![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210813123514.png)

	

	

- Server Hello，Certificate

	```c
	struct {
	    ProtocolVersion server_version; // 服务器回应的TLS版本
	    Random random; // 服务器端的32位的时间戳和28字节的随机数
	    SessionID session_id; // 如果Client Hello中session_id不为空，且server在缓存中找到了对应的信息，则直接返回session_id，表示复用，如果没找到，或server不想使用，则返回一个新的session_id，或者返回空
	    CipherSuite cipher_suite; // 服务端从cipher_suites中选定的套件
	    CompressionMethod compression_method; // 服务端从compression_method中选定的方法
	    // 扩展相关
	    select (extensions_present) {
	        case false:
	            struct {};
	        case true:
	            Extension extensions<0..2^16-1>;
	    };
	} ServerHello;
	```
	
	
	```c
	struct {
	          ASN.1Cert certificate_list<0..2^24-1>;   // 证书
	} Certificate;
	```
	
	

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210813124313.png)



- Server Key Exchange，Server Hello Done

	Server Key Exchange用于表示密钥交换中Server需要发送的信息
	
	```c
	struct {
	    select (KeyExchangeAlgorithm) {
	        case dh_anon:
	            ServerDHParams params;
	        case dhe_dss:
	        case dhe_rsa:
	            ServerDHParams params;
	            digitally-signed struct {
	                opaque client_random[32];
	                opaque server_random[32];
	                ServerDHParams params;
	            } signed_params;
	        case rsa:
	        case dh_dss:
	        case dh_rsa:
	            struct {} ;
	            /* message is omitted for rsa, dh_dss, and dh_rsa */
	        /* may be extended, e.g., for ECDH -- see [TLSECC] */
	    };
	} ServerKeyExchange;
	
	struct {
	    opaque dh_p<1..2^16-1>;
	    opaque dh_g<1..2^16-1>;
	    opaque dh_Ys<1..2^16-1>;
	} ServerDHParams;     /* Ephemeral DH parameters */
	```
	
	
	
	```c
	struct { } ServerHelloDone; // Server Hello Done表示服务端在密钥交换环节发送完信息，等待客户端信息
	```
	
	
	
	![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210813125211.png)



- Client Key Exchange，Change Cipher Spec，Finished

	Client Key Exchange表示客户端在密钥协商中需要提供的信息

	```c
	struct {
	    select (KeyExchangeAlgorithm) {
	        case rsa:
	            EncryptedPreMasterSecret;
	        case dhe_dss:
	        case dhe_rsa:
	        case dh_dss:
	        case dh_rsa:
	        case dh_anon:
	            ClientDiffieHellmanPublic;
	    } exchange_keys;
	} ClientKeyExchange;
	```

	Change Cipher Spec表示后续数据传输使用协商后的加密方式进行

	```c
	struct {
	    enum { change_cipher_spec(1), (255) } type;
	} ChangeCipherSpec;
	```

	Finished通常在Change Cipher Spec之后发送，用于验证key exchange是否成功，finished信息包含了整个协商交互过程中内容的Hash校验值，所以Finish信息也是对于交互中是否篡改进行的校验。

	```c
	struct {
	    opaque verify_data[verify_data_length];
	} Finished;
	
	verify_data
	    PRF(master_secret, finished_label, Hash(handshake_messages))
	        [0..verify_data_length-1];
	
	finished_label
	    For Finished messages sent by the client, the string
	    "client finished".  For Finished messages sent by the server,
	    the string "server finished".
	```

	

	![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210813125417.png)



- New Session Ticket，Change Cipher Spec，Finished

	验证成功后服务器返回Session Ticket

	Session ID时服务端保存的握手记录

	Session Ticket是客户端保存的握手记录

	![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img2/20210813130715.png)





```Mermaid
%% 如果采用RSA算法,-> 直线，-->虚线，->>实线箭头
  sequenceDiagram
    participant Alice
    participant Bob
    Note left of Alice: Client random
    Alice->>Bob: 1. Client Hello
    Note right of Bob: Client random
    Note right of Bob: Server random <br/>Server certificate <br/>Key parameters
    Bob->>Alice: 2. Server Hello，Certificate
    Bob->>Alice: 3. Server Key Exchange，Server Hello Done
    Note left of Alice: Server random<br/>Server certificate
    Alice-->>Alice: Check out if certificate is legal
	Note left of Alice: Key parameters <br/>Hash(handshake_messages)
    Alice->>Bob: 4. Client Key Exchange，Change Cipher Spec，Finished
	Bob->>Alice: 5. New Session Ticket，Change Cipher Spec，Finished
```



## TLS 1.2 中间人



> 仅仅使用单向认证无法避免中间人攻击，当用户下载证书并信任以后，可以校验通过

```Mermaid
%% 如果采用RSA算法,-> 直线，-->虚线，->>实线箭头
  sequenceDiagram
    participant Alice
    participant Evil
    participant Bob
    Alice->>Evil: Client Hello
    Evil->>Bob: Client Hello(Mock)
    Bob->>Evil: Server Hello，Certificate
    Bob->>Evil: Server Key Exchange，Server Hello Done
    Evil->>Alice: Server Hello，Certificate(Mock)
    Evil->>Alice: Server Key Exchange，Server Hello Done(Mock)
    Alice-->>Alice: Check out if certificate is legal
	Alice->>Evil: Client Key Exchange，Change Cipher Spec，Finished
    Evil->>Bob: Client Key Exchange，Change Cipher Spec，Finished(Mock)
	Bob->>Evil: New Session Ticket，Change Cipher Spec，Finished
	Evil->>Alice: New Session Ticket，Change Cipher Spec，Finished(Mock)
```



该场景下成功的条件是客户端信任Evil的证书（比如使用burpsuite时需要信任证书，但是这种情况下不需要验证证书来源是否合法，所以会提示不安全）



浏览器验证证书合法性：

1. 验证域名、有效期信息是否正确（证书上包含相关信息）
2. 判断证书来源是否合法：根据证书链判断根证书是否信任
3. 判断证书是否篡改：需要与CA服务器进行校验
4. 判断证书是否吊销：通过CRL（Certificate Revocation List证书注销列表）和OCSP（Online Certificate Status Protocol 在线证书状态协议）实现



# 参考链接

1. The Original HTTP as defined in 1991. https://www.w3.org/Protocols/HTTP/AsImplemented.html
2. Hypertext Transfer Protocol -- HTTP/1.0. https://www.w3.org/Protocols/HTTP/1.0/spec.html
3. The Transport Layer Security (TLS) Protocol Version 1.2. https://datatracker.ietf.org/doc/html/rfc5246
