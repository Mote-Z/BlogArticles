Title = "Chrome 特性 "
description = "在CTF中出题人往往会关注浏览器更新的一些新特性，本文尝试做一些记录"
tags = ["浏览器","Web"]
publishtime = 2020-05-10T10:55:54
lastedittime = 2020-05-10T10:55:54
uuid = "1b822185-3689-4b06-a273-dca00f397860"
-+_+-



在CTF中出题人往往会关注浏览器更新的一些新特性，以及语言的相关issue，下面做整理归纳


## Scroll To Text Fragment

> https://www.chromestatus.com/feature/4733392803332096

为了方便实现类似于锚点的功能

这个特性允许用户在URL中指定文字片段，在加载页面后，浏览器将高亮显示最先匹配的内容并滚动到相应位置。

以维基百科举例

```
https://en.wikipedia.org/wiki/Cat#:~:text=The domestic cat is a member of the Felidae
```

当页面加载以后，浏览器会高亮对应的文字片段`The domestic cat is a member of the Felidae`，并滚动到匹配元素居中的位置

这个特性还允许在URL中指定id（类似于选择器），加载页面后，浏览器会匹配对应id的元素，并且滚动到该元素位置置顶

还是以维基百科举例

```
https://en.wikipedia.org/wiki/Cat#Senses
```



**相关语法**（详细请看 https://github.com/WICG/ScrollToTextFragment/）

```
https://example.com#:~:text=prefix-,startText,endText,-suffix

:~:text=[prefix-,]textStart[,textEnd][,-suffix]

         context  |-------match-----|  context
```

- prefix 和 suffix 是为了限制匹配范围
- 进行匹配的是textStart 和 textEnd



**相关特性**

- 只匹配第一个实例

- 大小写不敏感

- 完整匹配，即不能匹配单词中的某部分

- 单词需要在同一个块中

	> 比如
	>
	> :~:text=The quick,lazy dog
	>
	> 在以下片段会匹配失败
	>
	> ```
	> <div>The<div> </div>quick brown fox</div>
	> <div>jumped over the lazy dog</div>
	> ```

- 可以跨元素范围匹配（可以不在同一个块）

	> #:~:text=tag,another

- 滚动只发生在第一次（这个可能跟用户操作用户手势之类的相关特性有关）



**注意事项**：

出于隐私考虑，google对 scroll text fragment 特性做了限制

> https://wicg.github.io/ScrollToTextFragment/#restricting-the-text-fragment



- scroll text fragment 只能在非同一页面由于 User Activation 产生的完整导航才能生效，没有 User Activation 无法使用该功能
- [browsing context isolation](https://html.spec.whatwg.org/multipage/browsers.html)

```c++
bool CheckSecurityRestrictions(LocalFrame& frame,
                               bool same_document_navigation) {
  // This algorithm checks the security restrictions detailed in
  // https://wicg.github.io/ScrollToTextFragment/#should-allow-text-fragment
  // We only allow text fragment anchors for user or browser initiated
  // navigations, i.e. no script navigations.
  if (!(frame.Loader().GetDocumentLoader()->HadTransientActivation() ||
        frame.Loader().GetDocumentLoader()->IsBrowserInitiated())) {
    return false;
  }
  // Allow same-document navigations only if they are browser initiated, e.g.
  // same-document bookmarks.
  if (same_document_navigation) {
    return frame.Loader()
        .GetDocumentLoader()
        ->LastSameDocumentNavigationWasBrowserInitiated();
  }
  // Allow text fragments on same-origin initiated navigations.
  if (frame.Loader().GetDocumentLoader()->IsSameOriginNavigation())
    return true;
  // Otherwise, for cross origin initiated navigations, we only allow text
  // fragments if the frame is not script accessible by another frame, i.e. no
  // cross origin iframes or window.open.
  if (frame.Tree().Parent() || frame.GetPage()->RelatedPages().size())
    return false;
  return true;
}
```

**默认支持该特性的版本**

```
Enabled by default in:
Chrome for desktop release 80
Chrome for Android release 80
Android WebView release 80
```





## Lazy Loading

> 示例
>
> https://mathiasbynens.be/demo/img-loading-lazy
>
> https://mingjunlu.github.io/lazy-loading-example/

从Chrome 76版本开始，默认支持惰性加载，这个特性是可以使用 `loading="lazy"` 来指定 image 和 iframe 的加载方式，主要有以下三种

- eager  立刻加载
- lazy    惰性加载，直到 image 或者 iframe 与浏览器窗口的距离小于一定阈值（distance threshold from the viewport）则开始加载，一般来说这个阈值的设定会使得窗口刚好滑到相应图片时，正好加载完成
- auto  **默认行为**，与立刻加载一致



**默认支持该特性的版本**

```
Enabled by default (tracking bug) in:
Chrome for desktop release 76
Chrome for Android release 76
```





## User Activation v2（UAv2）

### 背景

为了防止恶意脚本滥用敏感 APIs ，比如 （popups、fullscreen etc.），浏览器通过 `user activation` 来对这些 APIs 进行访问控制（当用户尚未激活该页面时，浏览器会阻止这些 APIs 的调用），这些控制 APIs 也就是 `activation-gated APIs`。  

`user activation` 是 `browsing session`（浏览会话）的一个状态，表示当前浏览会话中，用户是否正在与页面进行交互（比如打字输入，鼠标点击等），或者自页面加载以来是否已经完成了交互。

> **误解**：
>
> 有些团队会将 `user activation` 理解成 `user gesture` ，但是这样的理解其实是不正确的，因为**用户的滑动或轻拂这类手势并不会激活页面**，因此从这个角度来看 `user activation `并不能单纯理解成 `user gesture`。

目前，主流的浏览器在如何通过 `user activation` 来控制`activation-gated APIs`的问题上各有各的实现，详情请看参考链接2。

在 Chrome 72以前的版本中，该实现基于 `token-based model`（基于令牌的模型），然而该模型过于复杂，很难让 APIs 的访问控制的定义保持一致。比如 Chrome 允许通过 `postMessage()` 和 `setTimeout()`对 `activation-gated APIs` 进行不完全的访问，但是不支持  `Promises`、`XHR`、`Gamepad interaction`等方式传递 `user activation`状态。

在 Chrome 72之后，更新了 `User Activation v2`（后面简称UAv2）特性，该特性解决了以前版本的一致性的问题，使得可以通过 `user activation` 来控制所有的 `activation-gated APIs`。





### UAv2模型

UAv2 在 `frame hierarchy`的每个 window 对象中用 2-bit 来记录用户激活状态

- `HasSeenUserActivation`: 这个 bit 是一个 `sticky bit`，也就是设置以后就不再改变，这个 bit 在第一次用户操作时被置位，并且在window对象的生存期内永远不会重置，比如 `<video> autoplay` ，`Navigator.vibrate()`
- `HasConsumableUserActivation`: 这个 bit 是一个 `transient bit` ，将会在每次用户交互时被置位，并在超过浏览器定义的过期时间（通常是 1s ）或者通过调用消耗激活的API进行重置，比如 `window.open()`

```javascript
> console.log(navigator.userActivation);
UserActivation {hasBeenActive: true, isActive: false}
```



### 相关细节

- `UAv2`基于框架层次结构，没有以前的 token 传递（token passing）的概念

- `UAv2` 通过框架层次结构来实现跨 frame 的`user activation`可见性问题。举个例子，如果用户激活了某个 frame ，那么该 frame 的所有子 frame 都将被激活。（在没有完全解决如何传递`user activation`到 sub-frames 之前，都将暂时使用这种办法）

- 不止 sub-frames ，当前正在交互的 frame 与 frame tree 上其所有的祖先 frame  都会变为 activated 状态

- `transient bit`的消耗导致的`transient bit`置位，会作用于整个 frame tree

- 想要从一个 activated frame 中通过外部代码（outside an event handler code）调用 activation-gated API，只要 `user activation`状态是激活状态（没有过期也没有被消耗），就会起作用（在UAv2以前是无法成功的）

- 多个有效时间内未被使用的`user activation`将进行融合

- `user activation`的有效时间是本地性质的，也就是本地的`user activation`过期了不会在 frames 之间传递，详情请查看参考链接7

- User  Activation 可以通过 postMessage 跨域传递，但是只能从cross-origin sub frame 传递给 parent frame，parent frame 无法传递给 cross-origin sub frame ，需要设置 includeUserActivation 为 true




### 关于 user activation gated APIs 的不同种类

- Transient activation consuming APIs：这一类 APIs 需要 transient bit 才能触发，并且会消耗 transient bit 来防止重复调用（比如 window.open())
- Transient activation gated APIs：这一类 APIs 需要 transient bit 才能触发，但是不会消耗 transient bit，所以可以多此调用直到 transient bit 过期（比如 Element.requestFullscreen()）
- Sticky activation gated APIs：这类APIs 需要 sticky activation bit 才能触发，所以这类 APIs 只有在进行第一次用户交互 sticky activation bit 被置位以后才可以调用 （比如`<video> autoplay` 和 `Navigator.vibrate()`)



### 关于postMessage 中的 includeUserActivation属性

https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/third_party/blink/renderer/core/messaging/post_message_options.idl

虽然 Chrome 给 postMessage 增加了 includeUserActivation 属性来通知接收者，并且其默认值为 false ，但是实际上，并没有按照预期进行，chromium在当前 frame为activated状态时 postMessage ，并且没有设置 options 则 chromium 将会attach user activation ，即使 includeUserActivation 为默认值 false

https://bugs.chromium.org/p/chromium/issues/detail?id=1077139

> I did some digging in the source and it looks like the reason for this is that the variant of [postMessage] used by the [chrome.runtime.connect] API differs from those for [Window], [Worker], and [MessagePort] in that it doesn't accept an [options] argument, which is where the [includeUserActivation] field is set in the other variants.  Instead, the user activation state is attached when [GinPort::PostMessageHandler] invokes [messaging_util::MessageFromV8] which invokes [messaging_util::MessageFromJSONString] which will ALWAYS attach a user activation if it is present.

因此，这个非预期的行为会导致 user activation 被重用



### 相关演示

1. postMessage()  child-to-parent例子

通过postMessage可以实现child-to-parent的传递，在这个例子中由 Cross-origin subframe 状态改变传递到了 parent frame 所以可以调用 parent frame 的 User-activation-gated API

https://mustaqahmed.github.io/user-activation-v2/api-consistency/postMessages.html

2. postMessage()  parent-to-child 例子

这个例子演示了 parent-to-child 的传递，但是 parent frame 的 activated 不能传递到cross-origin frame，所以无法调用 cross-origin frame 的 User-activation-gated API

https://mustaqahmed.github.io/user-activation-v2/api-consistency/postMessages2.html

2. setTimeout()例子

通过 setTimeout来实现 User-activation-gated API 调用

https://mustaqahmed.github.io/user-activation-v2/api-consistency/setTimeout.html

3. activated frame ，所有 sub-frames 都会 activated

例子：http://39.108.99.6/user-activation/

4. activated frame ，所有 parent-frames 都会 activated

例子：http://39.108.99.6/user-activation/example2.html

5. propagation的演示

https://mustaqahmed.github.io/user-activation-v2/propagation/

6. propagation live的演示

在这个演示中，演示了parent frame ， sub frame ，以及 cross-origin frame 之间 user activation 的传递关系，其中 parent frame 的 activated 不能传递到cross-origin frame，而cross-origin frame的activated 可以传递给 parent frame

https://mustaqahmed.github.io/user-activation-v2/propagation-live//







### user activation所控制的APIs

完整列表可以查看参考链接6



### 默认支持该特性的版本

```
Enabled by default (tracking bug) in:
Chrome for desktop release 72
Chrome for Android release 72
Chrome for iOS release 72
```





### 参考链接

> 1. https://www.chromestatus.com/feature/5722065667620864
>
> 2. 主流浏览器在实现上的差异：https://docs.google.com/document/d/1hYRTEkfWDl-KO4Y6cG469FBC3nyBy9_SYItZ1EEsXUA/edit
>
> 3. https://developers.google.com/web/updates/2019/01/user-activation
>
> 4. https://mustaqahmed.github.io/user-activation-v2/
>
> 5. https://whatpr.org/html/3851/interaction.html#tracking-user-activation
>
> 6. 受user activation控制的完整API列表 ：https://docs.google.com/document/d/1mcxB5J_u370juJhSsmK0XQONG2CIE3mvu827O-Knw_Y/edit#
>
> 7. Each copy of the bit will expire "locally"[https://docs.google.com/document/d/1XL3vCedkqL65ueaGVD-kfB5RnnrnTaxLc7kmU91oerg/edit#:~:text=Each%20copy%20of%20the%20bit%20will%20expire%20%E2%80%9Clocally%E2%80%9D](https://docs.google.com/document/d/1XL3vCedkqL65ueaGVD-kfB5RnnrnTaxLc7kmU91oerg/edit#:~:text=Each copy of the bit will expire "locally")
>
> 8. 在 postMessage 方法里增加了一个 includeUserActivation 属性来告诉postMessage的消息发送方传递user activation
>
> 	https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/third_party/blink/renderer/core/messaging/post_message_options.idl
>
> 	https://chromium.googlesource.com/chromium/src.git/+/e2fd13720ce018729ccd795b7abaa52cf5f4614f
>
> 	https://bugs.chromium.org/p/chromium/issues/detail?id=1077139