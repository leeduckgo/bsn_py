# bsn_py
**BSN(Blockchain-based Service Network) Python 示例代码**

本文件用于对运行Python开发示例进行相关描述：

 ## 一、开发环境准备 

1、Pycharm / VsCode（可以使用您习惯的IDE）  
2、Python  3.5+
3、Django  2.2.5 
4、Django-bootstrap3   11.1.0 
5、requests  2.22.0 
6、cryptography  2.7 
7、fabric-sdk-py  0.8.1  

（注：可根据requirements.txt文件自动安装依赖 执行命令 pip install -r requirements.txt）

## 二、项目描述

该项目使用 Python-Django 框架，直接调用服务网关api接口，实现数据交互。

1、结构说明：
common 文件夹下文件说明：myecdsa256.py（椭圆曲线 SHA256WITHECDSA 签名方法和验签方法）
			loggers.py（日志方法）

certificate 文件夹下文件说明：bsn_https.pem（https请求的公钥证书）
			 gateway_public_cert.pem（网关公钥证书）
			 private_key.pem（用户私钥证书）
			 public_cert.pem（用户公钥证书）

packages 文件夹下文件说明 ：fabric-sdk-py-master.zip （fabric 官方 py 库包，需解压后手动安装到 python 第三方库中 ）

logs 文件夹下存放日志文件。

2、逻辑说明：
（1）在发起服务网关api请求时，需附加https的公钥证书。

（2）调用服务网关api接口，需在请求参数中加入mac值，mac值为对字符串使用用户私钥证书进行SHA256WITHECDSA 签名的结果，若mac值不正确则不能通过服务网关的校验，不能增删改查数据。【mac值具体生成规则详见开发者手册说明】

（3）服务网关api接口返回报文后，需使用网关公钥证书，验证服务网关返回的mac签名，字符串还是步骤2中的字符串。【具体验签规则详见开发者手册说明】

## 三、代码运行

安装好开发环境后，进入项目根目录下，cmd下运行 python manage.py runserver 运行项目。
在浏览器中输入 http://127.0.0.1:8000/ 即可访问项目的web界面。

