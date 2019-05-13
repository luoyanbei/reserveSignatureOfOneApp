# reserveSignatureOfOneApp
使用frida、ida和动态调试，逆向某app,找到网络请求中signature的生成算法

通过Charles抓包发现，请求中有一个验签参数signature,每次请求网络都会变化。

```
请求地址：
http://xxxx.xxxxxx.com/api/article/v2/get_category

参数：
{
"content":{"muid" :"f7e2cb93-5cf3-4b9f-a035-30555c13a167"},
"signature":"6c171c8f2bb05caca19047e3c4a04a7adff9eb3b3973ff3064fa4ab1ba17de64",
"sig_kv":"503_1",
"cten":"p"
}
```
本次调试的目的就是找到signature的生成算法。

### 使用frida调试
1. frida的安装

越狱手机安装Frida:在Cydia中添加源"https://build.frida.re/",接着在源中找到Frida并安装。

Mac安装frida:需要先有Python环境，使用“pip install frida”安装frida
(Frida的详细使用请参考官网：www.frida.re)

2. 使用frida监控+[NSURL URLWithString:]的参数和调用堆栈

新建一个文件夹test，终端进入test目录

打印iphone运行的app信息,终端输入命令：

```
frida-ps -Ua
```
输出如下：

```
  PID  Name        Identifier                   
-----  ----------  -----------------------------
17521  H******e  com.d**********s.zodiac
 2048  支付宝         com.alipay.iphoneclient      
 4296  日历          com.apple.mobilecal          
 3551  相机          com.apple.camera  
```
Horoscope+的PID是17521

监控Horoscope+中的"+[NSURL URLWithString:]"方法，终端命令：

```
frida-trace -U 17521 -m "+[NSURL URLWithString:]"

```
终端输出：

```
Instrumenting functions...                                              
+[NSURL URLWithString:]: Loaded handler at "/Users/king/Documents/test/__handlers__/__NSURL_URLWithString__.js"
Started tracing 1 function. Press Ctrl+C to stop.  
```

在终端界面，按"control+c"退出frida的监控状态。
在test文件夹中的__handlers__文件夹中找到__NSURL_URLWithString__.js文件，主要内容如下：

```
{
    onEnter: function (log, args, state) {
        log("+[NSURL URLWithString:" + args[2] + "]");
    },

    onLeave: function (log, retval, state) {
    
    }
}
```
编辑文件内容，结果如下：
```
{
    onEnter: function (log, args, state) {
        log("+[NSURL URLWithString:" + ObjC.Object(args[2]) + "]");
        log('\tBacktrace:\n\t' + Thread.backtrace(this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
    },

    onLeave: function (log, retval, state) {
        log("+[NSURL URLWithString:]--return=(" + ObjC.Object(retval) + ")");
    }
}
```
ObjC.Object(args[2])
打印参数的值

log('\tBacktrace:\n\t' + Thread.backtrace(this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
打印调用堆栈

log("+[NSURL URLWithString:]--return=(" + ObjC.Object(retval) + ")");
打印返回值

这样修改，frida监控NSURL时能打印出参数和堆栈，让我们能很快找到网络请求的位置。

终端再次开启frida监控：
```
frida-trace -U 17521 -m "+[NSURL URLWithString:]"
```
当请求网络时，会看到终端的打印信息：

```
4913 ms  +[NSURL URLWithString:http:/horoscope.ohippo.com/api/article/v2/get_list]
  4913 ms  	Backtrace:
	0x100bdfecc Horoscope!0xb87ecc
	0x100be0294 Horoscope!0xb88294
	0x1001dcee4 Horoscope!0x184ee4
	0x1001dd6d4 Horoscope!0x1856d4
	0x100087d18 Horoscope!0x2fd18
	0x100086ef4 Horoscope!0x2eef4
	0x193ce8ec0 UIKit!-[UIViewController loadViewIfRequired]
	0x193ce8a9c UIKit!-[UIViewController view]
	0x100176df0 Horoscope!0x11edf0
	0x10014dbcc Horoscope!0xf5bcc
	0x193d1e010 UIKit!-[UIApplication sendAction:to:from:forEvent:]
	0x193d1df90 UIKit!-[UIControl sendAction:to:forEvent:]
	0x193d08504 UIKit!-[UIControl _sendActionsForEvents:withEvent:]
	0x193d1d874 UIKit!-[UIControl touchesEnded:withEvent:]
	0x193d1d390 UIKit!-[UIWindow _sendTouchesForEvent:]
	0x193d18728 UIKit!-[UIWindow sendEvent:]
  4916 ms  +[NSURL URLWithString:]--return=(http:/horoscope.ohippo.com/api/article/v2/get_list)
```
打印的信息很多，这里只截取了一部分有用的打印信息。

使用lldb+debugserver附加当前进程，打印模块偏移地址如下：

```
[  0] 0x0000000000058000 /var/containers/Bundle/Application/FA17E6F7-4386-40B1-8B87-0A138169E67F/Horoscope.app/Horoscope(0x0000000100058000)
[  1] 0x0000000101634000 /Users/king/Library/Developer/Xcode/iOS DeviceSupport/10.3.2 (14F89)/Symbols/usr/lib/dyld
...
...
```
计算本次 +[NSURL URLWithString:]方法调用在ida中的地址：
0x100bdfecc - 0x0000000000058000 = 0x100B87ECC

在ida中找到0x100B87ECC位置，可以定位到这个方法：

```
+[HSServerAPIRequest requestWithURL:dataBody:method:enableEncryption:hashKey:sigKey:]
```
在ida中查看+[HSServerAPIRequest requestWithURL:dataBody:method:enableEncryption:hashKey:sigKey:]的伪代码，可以看到一个+[HSServerAPIRequest parametersWithDataBody:enableEncryption:hashKey:sigKey:]方法

```
ida中的伪代码：

id __cdecl +[HSServerAPIRequest parametersWithDataBody:enableEncryption:hashKey:sigKey:](HSServerAPIRequest_meta *self, SEL a2, id a3, bool a4, id a5, id a6)
{
  v6 = a6;
  v7 = a5;
  v8 = a4;
  v9 = a3;
  v10 = self;
  v11 = objc_retain(a3, a2);
  v13 = objc_retain(v7, v12);
  v15 = objc_retain(v6, v14);
  v16 = ((id (__cdecl *)(HSUtils_meta *, SEL, id))objc_msgSend)(
          (HSUtils_meta *)&OBJC_CLASS___HSUtils,
          "jsonStringWithObject:",
          v9);
  v17 = objc_retainAutoreleasedReturnValue(v16);
  objc_release(v11);
  if ( v8 )
    v18 = objc_msgSend(v10, "encryptedParametersWithDataBodyString:hashKey:sigKey:", v17, v13, v15);
  else
    v18 = objc_msgSend(v10, "plainParametersWithDataBodyString:hashKey:sigKey:", v17, v13, v15);
  v19 = (struct objc_object *)objc_retainAutoreleasedReturnValue(v18);
  objc_autorelease(v19);
  return v19;
}
```
从伪代码中可以看到"encryptedParametersWithDataBodyString:hashKey:sigKey:"和"plainParametersWithDataBodyString:hashKey:sigKey:"方法，可以跟进去看它们的伪代码具体内容。

```
id __cdecl +[HSServerAPIRequest encryptedParametersWithDataBodyString:hashKey:sigKey:](HSServerAPIRequest_meta *self, SEL a2, id a3, id a4, id a5)
{
  v5 = a5;
  v6 = a4;
  v7 = self;
  v8 = objc_retain(a3, a2);
  v10 = objc_retain(v6, v9);
  v12 = objc_retain(v5, v11);
  v13 = +[HSConfig sharedInstance](&OBJC_CLASS___HSConfig, "sharedInstance");
  v14 = (void *)objc_retainAutoreleasedReturnValue(v13);
  v15 = v14;
  v16 = objc_msgSend(v14, "data");
  v17 = (void *)objc_retainAutoreleasedReturnValue(v16);
  v18 = v17;
  v19 = objc_msgSend(v17, "valueForKeyPath:", CFSTR("libCommons.Connection.EncryptionKeyVersion"));
  v20 = (void *)objc_retainAutoreleasedReturnValue(v19);
  if ( !objc_msgSend(v20, "length") )
    objc_msgSend(
      &OBJC_CLASS___NSException,
      "raise:format:",
      CFSTR("ConnectionConfigException"),
      CFSTR("EncryptionKeyVersion is empty"));
  v21 = objc_msgSend(v7, "class");
  v22 = objc_msgSend(v21, "encryptKey");
  v23 = objc_retainAutoreleasedReturnValue(v22);
  v24 = v23;
  v25 = +[HSAESUtils AES256EncryptString:withKey:](&OBJC_CLASS___HSAESUtils, "AES256EncryptString:withKey:", v8, v23);
  v26 = objc_retainAutoreleasedReturnValue(v25);
  v27 = objc_msgSend(v7, "class");
  v28 = objc_msgSend(v27, "signedParametersWithContent:hashKey:sigKey:", v26, v10, v12);
  v29 = (void *)objc_retainAutoreleasedReturnValue(v28);
  objc_release(v12);
  objc_msgSend(v29, "setObject:forKey:", CFSTR("a"), CFSTR("cten"));
  objc_msgSend(v29, "setObject:forKey:", v20, CFSTR("cten_kv"));

  return (id)objc_autoreleaseReturnValue(v29);
}
```
这里可以看到使用了一个AES256加密算法。

```
id __cdecl +[HSServerAPIRequest plainParametersWithDataBodyString:hashKey:sigKey:](HSServerAPIRequest_meta *self, SEL a2, id a3, id a4, id a5)
{
  v5 = a5;
  v6 = a4;
  v7 = self;
  v8 = objc_retain(a3, a2);
  v10 = objc_retain(v6, v9);
  v12 = objc_retain(v5, v11);
  v13 = objc_msgSend(v7, "class");
  v14 = objc_msgSend(v13, "signedParametersWithContent:hashKey:sigKey:", v8, v10, v12);
  v15 = (void *)objc_retainAutoreleasedReturnValue(v14);
  objc_release(v12);
  objc_release(v10);
  objc_release(v8);
  objc_msgSend(v15, "setObject:forKey:", CFSTR("p"), CFSTR("cten"));
  return (id)objc_autoreleaseReturnValue(v15);
}
```
从上面的伪代码中，看到一个"signedParametersWithContent:hashKey:sigKey:"方法，我们继续跟进。

```
id __cdecl +[HSServerAPIRequest signedParametersWithContent:hashKey:sigKey:](HSServerAPIRequest_meta *self, SEL a2, id a3, id a4, id a5)
{
  
  v5 = a5;
  v6 = a4;
  v7 = objc_retain(a3, a2);
  v9 = (void *)objc_retain(v6, v8);
  v11 = (void *)objc_retain(v5, v10);
  v59 = CFSTR("content");
  v60 = v7;
  v12 = objc_msgSend(&OBJC_CLASS___NSDictionary, "dictionaryWithObjects:forKeys:count:", &v60, &v59, 1LL);
  v13 = objc_retainAutoreleasedReturnValue(v12);
  v14 = v13;
  v15 = objc_msgSend(&OBJC_CLASS___NSMutableDictionary, "dictionaryWithDictionary:", v13);
  v16 = (void *)objc_retainAutoreleasedReturnValue(v15);
  objc_release(v14);
  if ( objc_msgSend(v11, "length") )
  {
    v18 = (void *)objc_retain(v11, v17);
  }
  else
  {
    v19 = (HSConfig *)+[HSConfig sharedInstance](&OBJC_CLASS___HSConfig, "sharedInstance");
    v20 = (void *)objc_retainAutoreleasedReturnValue(v19);
    v21 = v20;
    v22 = objc_msgSend(v20, "data");
    v23 = (void *)objc_retainAutoreleasedReturnValue(v22);
    v24 = v23;
    v25 = objc_msgSend(v23, "valueForKeyPath:", CFSTR("libCommons.Connection.SigKey"));
    v18 = (void *)objc_retainAutoreleasedReturnValue(v25);
    objc_release(v24);
    objc_release(v21);
  }
  if ( objc_msgSend(v18, "length") )
    objc_msgSend(v16, "setObject:forKey:", v18, CFSTR("sig_kv"));
  if ( objc_msgSend(v9, "length") )
  {
    v27 = (void *)objc_retain(v9, v26);
    if ( objc_msgSend(v27, "length") != (void *)32 )
    {
      v28 = objc_msgSend(
              &OBJC_CLASS___NSException,
              "exceptionWithName:reason:userInfo:",
              CFSTR("wrong specified hash key"),
              CFSTR("the lengh of hash key is not correct"),
              0LL);
LABEL_16:
      v55 = (void *)objc_retainAutoreleasedReturnValue(v28);
      objc_msgSend(v55, "raise");
      objc_release(v55);
      v54 = 0LL;
      goto LABEL_17;
    }
  }
  else
  {
    v29 = (HSConfig *)+[HSConfig sharedInstance](&OBJC_CLASS___HSConfig, "sharedInstance");
    v30 = (void *)objc_retainAutoreleasedReturnValue(v29);
    v31 = v30;
    v32 = objc_msgSend(v30, "data");
    v33 = (void *)objc_retainAutoreleasedReturnValue(v32);
    v34 = v33;
    v35 = objc_msgSend(v33, "valueForKeyPath:", CFSTR("libCommons.Connection.HashKey"));
    v27 = (void *)objc_retainAutoreleasedReturnValue(v35);
    objc_release(v34);
    objc_release(v31);
    if ( objc_msgSend(v27, "length") != (void *)32 )
    {
      v28 = objc_msgSend(&OBJC_CLASS___NSException, "exceptionWithName:reason:userInfo:");
      goto LABEL_16;
    }
  }
  v36 = sub_100B81304(v27);
  v37 = objc_retainAutoreleasedReturnValue(v36);
  v38 = objc_msgSend(v16, "objectForKeyedSubscript:", CFSTR("content"));
  v39 = objc_retainAutoreleasedReturnValue(v38);
  objc_release(v39);
  if ( v39 )
  {
    v57 = v11;
    v58 = v7;
    v41 = objc_msgSend(v16, "objectForKeyedSubscript:", CFSTR("content"));
    v42 = objc_retainAutoreleasedReturnValue(v41);
    v44 = objc_retain(v37, v43);
    v45 = (void *)objc_retainAutorelease(v44);
    v46 = (const char *)objc_msgSend(v45, "cStringUsingEncoding:", 4LL);
    objc_release(v45);
    v47 = (void *)objc_retainAutorelease(v42);
    v48 = (const char *)objc_msgSend(v47, "cStringUsingEncoding:", 4LL);
    v49 = strlen(v46);
    v50 = strlen(v48);
    CCHmac(2LL, v46, v49, v48, v50, v61);
    v51 = objc_msgSend(&OBJC_CLASS___NSMutableString, "stringWithCapacity:", 64LL);
    v52 = (void *)objc_retainAutoreleasedReturnValue(v51);
    v53 = 0LL;
    do
      objc_msgSend(v52, "appendFormat:", CFSTR("%02x"), (unsigned __int8)v61[v53++]);
    while ( v53 != 32 );
    objc_msgSend(v16, "setObject:forKey:", v52, CFSTR("signature"));

    v7 = v58;
    v11 = v57;
  }
  v54 = objc_retain(v16, v40);
LABEL_17:
  if ( __stack_chk_guard == v62 )
    result = (id)objc_autoreleaseReturnValue(v54);
  return result;
}
```
可以看到 CCHmac(2LL, v46, v49, v48, v50, v61) ，这个是加密算法。

我通过动态调试，确定网络请求，要执行到这个CCHmac处做加密，不妨打印上面的这几个方法的参数和返回值，就能更直观的看到结果。
下面是我还原的部分方法：

```
+[HSServerAPIRequest requestWithURL:dataBody:method:enableEncryption:hashKey:sigKey:](HSServerAPIRequest_meta *self, SEL, id, id, signed __int64, bool, id, id)
{
	
	//参数：
	NSDictionary * pDict = {
    "category_id" = 2586351c525f3793b98fa2592111e70e;
    direction = old;
    muid = "f7e2cb93-5cf3-4b9f-a035-30555c13a167";
    "nearest_article_id" = "these-are-the-6-zodiac-signs-who-are-most-likely-to-ghost-you-a16139";
    "page_size" = 10;
	}


    // 调用这个方法
	+[HSServerAPIRequest parametersWithDataBody:enableEncryption:hashKey:sigKey:];
	{

		NSString * pStr = +[HSUtils jsonStringWithObject:pDict];
		// = {
  				"nearest_article_id" : "these-are-the-6-zodiac-signs-who-are-most-likely-to-ghost-you-a16139",
  				"page_size" : 10,
  				"muid" : "f7e2cb93-5cf3-4b9f-a035-30555c13a167",
  				"category_id" : "2586351c525f3793b98fa2592111e70e",
  				"direction" : "old"
			}



		if()
		{
            //执行如下的方法
			[HSServerAPIRequest plainParametersWithDataBodyString:arg1=pStr hashKey:arg2=nil sigKey:arg3=nil ];
			{

				NSDictionary * dict = {content = "{\n  \"nearest_article_id\" : \"these-are-the-6-zodiac-signs-who-are-most-likely-to-ghost-you-a16139\",\n  \"page_size\" : 10,\n  \"muid\" : \"f7e2cb93-5cf3-4b9f-a035-30555c13a167\",\n  \"category_id\" : \"2586351c525f3793b98fa2592111e70e\",\n  \"direction\" : \"old\"\n}";}

				NSMutableDictionary * mutDict = [NSMutableDictionary dictionaryWithDictionary:dict];


				id data;

				if([arg3 length]==0)
				{
					data = [[HSConfig sharedInstance] data];
					NSString * sigKey = [data valueForKeyPath:@"libCommons.Connection.SigKey"];
					// = @"503_1"

				}


				int count = [sigKey length];// = 5

				if(count!=0)
				{
					[mutDict setObject:sigKey forKey:@"sig_kv"];
				}

				if([arg2 length]==0)
				{
					NSString * hashKey = [data valueForKeyPath:@"libCommons.Connection.HashKey"];
					// = "E56j-4$X=XzA7H#H4]p2e@)V1=Rg6qS="


					if([hashKey length] == 32)// = 32
					{
						NSString * hashKey_2 = sub_100B81304(hashKey);// = "HJdq=ZT?l?yp1)V)ZbRYw#E/il;&d,Nl"

						// x22 = mutDict
						NSString * content = [mutDict objectForKeyedSubscript:@"content"];
						// x19 = {"nearest_article_id" : "precise-ways-to-put-yourself-out-there-to-meet-mr-right-based-on-zodiac-signs-a16206","page_size" : 10,"muid" : "f7e2cb93-5cf3-4b9f-a035-30555c13a167","category_id" : "2586351c525f3793b98fa2592111e70e","direction" : "old"}

						if(content)
						{
							char * hashKey_3 =[hashKey_2 cStringUsingEncoding:4];
							char * content_3 = [content cStringUsingEncoding:4];// = x19

							int length_hashKey_3 = strlen(hashKey_3);// = x27 = 32
							int length_content_3 = strlen(content_3);// = x4 = 263

							_CCHmac(2,hashKey_3,length_hashKey_3,content_3,length_content_3);

                            v51 = [NSMutableString stringWithCapacity:64LL];// = v52
                            v53 = 0LL;
                            do
                                [v52 appendFormat:@"%02x", (unsigned __int8)v61[v53++]);
                            while ( v53 != 32 );
                            [v16 setObject:v52 forKey:@"signature"];

						}
						else
						{

						}

					}
					else
					{
						return;
					}

				}
				else
				{

				}


			}


		}


	}


}

```
上面的伪代码中，能看到加密的参数是 hashKey_3 和 content_3，v61用于保存加密后的结果，最终得到v52就是最终的signature的值。

分析：CCHmac是一种常见的加算法，各种编程语言都有具体的实现，因此很容易用还原这个加密算法，更好的方式是直接用。在python中可以直接调用这个加密算法，我验证过，是完全OK的。

### 总结

本文重点在用Frida监控方法调用，找到关键函数，并在ida中通过静态分析，查看伪代码找到加密算法的蛛丝马迹，并结合动态调试，打印出算法的参数和返回值，最终还原出清晰的逻辑。

感谢您 帮忙在右上角 点个“⭐️”，非常感谢。

可关注公众号，获取本次逆向app的素材文件，方便练习。

## 多谢支持 ^_^
<div align=center><img width="240" height="200" src="./images/zhifubao@2x.png"/><t/><img width="240" height="200" src="./images/wechatpay@2x.png"/></div>

## 关注公众号：逆向APP
<div align=center><img width="258" height="258" src="./images/qrcode_gongzhonghao.jpg"/>
