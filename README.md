# Zongsoft.Security 安全模块

![license](https://img.shields.io/github/license/Zongsoft/Zongsoft.Security) ![download](https://img.shields.io/nuget/dt/Zongsoft.Security) ![version](https://img.shields.io/github/v/release/Zongsoft/Zongsoft.Security?include_prereleases) ![github stars](https://img.shields.io/github/stars/Zongsoft/Zongsoft.Security?style=social)

README: [English](https://github.com/Zongsoft/Zongsoft.Security/blob/master/README.md) | [简体中文](https://github.com/Zongsoft/Zongsoft.Security/blob/master/README-zh_CN.md)

-----

[Zongsoft.Security](https://github.com/Zongsoft/Zongsoft.Security) 提供身份验证、访问授权、基于角色的访问控制(RBAC)等安全相关功能的实现。

<a name="files"></a>
## 文件说明

### 数据库

在 `database` 目录中包含数据库定义脚本文件：

1. [`Zongsoft.Security-mssql.sql`](https://github.com/Zongsoft/Zongsoft.Security/blob/master/database/Zongsoft.Security-mssql.sql) 为 SQL Server 版本；
2. [`Zongsoft.Security-mysql.sql`](https://github.com/Zongsoft/Zongsoft.Security/blob/master/database/Zongsoft.Security-mysql.sql) 为 MySQL/MariaDB 版本；
3. `Zongsoft.Security.mdf` 和 `Zongsoft.Security_log.ldf` 为 SQL Server 本地数据库文件，方便进行开发调试之用。

### 插件文件
位于 `src` 目录中的 [`Zongsoft.Security.plugin`](https://github.com/Zongsoft/Zongsoft.Security/blob/master/src/Zongsoft.Security.plugin) 文件。如果你不了解 **Zongsoft** 插件开发的话，暂时将它简单理解为依赖注入容器的配置文件即可。

### 配置文件
位于 `src` 目录中的 [`Zongsoft.Security.option`](https://github.com/Zongsoft/Zongsoft.Security/blob/master/src/Zongsoft.Security.option) 文件，它定义了安全模块的数据库连接字符串及相关运行配置信息。

### 映射文件
位于 `src` 目录中的 [`Zongsoft.Security.mapping`](https://github.com/Zongsoft/Zongsoft.Security/blob/master/src/Zongsoft.Security.mapping) 文件，它是 [Zongsoft.Data](https://github.com/Zongsoft/Zongsoft.Data) 数据引擎的映射文件，是该项目数据访问的基础结构，更多有关数据访问及数据映射文件的信息请参考 [Zongsoft.Data](https://github.com/Zongsoft/Zongsoft.Data) 项目。

### 部署文件
位于 `src` 目录中的 [`.deploy`](https://github.com/Zongsoft/Zongsoft.Security/blob/master/src/.deploy) 文件，这是一个 `INI` 格式的配置文件，它定义了该项目内需要发布的文件，由 [Zongsoft.Utilities.Deployer](https://github.com/Zongsoft/Zongsoft.Utilities.Deployer) 部署工具解析使用。
> 提示：可以参考 [Zongsoft.CoreLibrary](https://github.com/Zongsoft/Zongsoft.CoreLibrary) 核心库的 `Zongsoft.Options.Profiles` 命名空间了解 `INI` 配置文件的解析。

<a name="usage"></a>
## 使用

### 编译

如果你是首次运行这些项目，那么需要确保下面的依赖项都已存在，否则根据实际情况执行或忽略它们。

1. 必须的依赖项目：
	* [**Zongsoft.CoreLibrary**](https://github.com/Zongsoft/Zongsoft.CoreLibrary)
	* [**Zongsoft.Plugins**](https://github.com/Zongsoft/Zongsoft.Plugins)

2. 如果是Web后端应用，那么还需要依次编译如下依赖项目：
	* [**Zongsoft.Web**](https://github.com/Zongsoft/Zongsoft.Web)
	* [**Zongsoft.Plugins.Web**](https://github.com/Zongsoft/Zongsoft.Plugins.Web)

3. 因为要完整运行本模块所以还需要数据访问引擎、Redis缓存服务等，那么请确保以下项目已编译完成：
	* [**Zongsoft.Data**](https://github.com/Zongsoft/Zongsoft.Data)
	* [**Zongsoft.Data.MsSql**](https://github.com/Zongsoft/drivers/Zongsoft.Data.MsSql) _(取决于你的数据库版本)_
	* [**Zongsoft.Data.MySql**](https://github.com/Zongsoft/drivers/Zongsoft.Data.MySql) _(取决于你的数据库版本)_
	* [**Zongsoft.Externals.Json**](https://github.com/Zongsoft/Zongsoft.Externals.Json)
	* [**Zongsoft.Externals.Redis**](https://github.com/Zongsoft/Zongsoft.Externals.Redis)

4. 如果还从来没有编译过部署工具，那么必须完成对 [**Zongsoft.Utilities.Deployer**](https://github.com/Zongsoft/Zongsoft.Utilities.Deployer) 项目的编译，否则忽略该步骤。

### 依赖环境

1. 首先你得准备好数据库，如果你使用 **V**isual **S**tudio 2017/2019 的话，默认已经安装了 SQL Server 本地数据库引擎；如果没有的话建议去 [SQL Server](https://www.microsoft.com/sql-server) 官网下载并安装它的 **D**eveloper 或 **E**xpress 免费版本，然后运行 `Zongsoft.Security-mssql.sql` 文件构建所需的数据表和初始数据。

2. 如果你已经有了 [**MySQL**](https://www.mysql.com) 或 [**MariaDB**](https://mariadb.org) 数据库的话，那么运行 `Zongsoft.Security-mysql.sql` 文件构建所需的数据表和初始数据。

3. 准备好 [**Redis**](https://redis.io) 服务器，如果你是 Windows 开发平台的话可以从[这里](https://github.com/MicrosoftArchive/redis/releases)下载安装 [Redis for Windows(X64)](https://github.com/MicrosoftArchive/redis/releases) 进行开发测试。

4. 根据你的数据库和 Redis 服务器实际情况，用记事本打开 `Zongsoft.Security.option` 和 `Zongsoft.Externals.Redis.option` 配置文件调整连接字符串及相关设置项。

### 工具准备

1. 运行你的 [**Postman**](https://www.getpostman.com)，打开 “**M**anage **E**nvironments” 窗口 _(点击右上角第二排右一)_ 再点击 “**I**mport” 找到位于 [Guidelines](https://github.com/Zongsoft/Guidelines) 项目中的 [`zongsoft.postman-globals.json`](https://github.com/Zongsoft/Guidelines/blob/master/zongsoft.postman-globals.json) 和 [`zongsoft.postman-environment.json`](https://github.com/Zongsoft/Guidelines/blob/master/zongsoft.postman-environment.json) 文件导入之。

2. 点击 [**Postman**](https://www.getpostman.com) 主窗口左上角的 “**I**mport” 按钮，找到本项目的 `docs` 目录中的 [`Zongsoft.Security.postman-collection.json`](https://github.com/Zongsoft/Zongsoft.Security/blob/master/docs/Zongsoft.Security.postman-collection.json) 文件并导入之。

> 注意：应根据自己的实际环境，及时调整我们预设的 [**Postman**](https://www.getpostman.com) 环境参数。当然，以上关于 [**Postman**](https://www.getpostman.com) 的操作并非必须，你完全可以采用自己熟悉的 HTTP API 测试工具。

### 调试

1. 在 **V**isual **S**tudio 中打开 [**Zongsoft.Web.Launcher**](https://github.com/Zongsoft/Zongsoft.Web.Launcher) 宿主项目并调试运行(F5)。

2. 打开你想要调试的代码文件，然后设置调试断点(F9)，等待测试请求进入断点即可。

3. 在 Postman 中找到 “**Zongsoft.Security**” 集合中的 “**Authentication.Signin**” 请求项进行登录测试吧，如果顺利的话将会得到返回的凭证对象，大致如下所示：
```json
{
    "credentialId": "6260000000ABCDEFG",
    "scene": "web",
    "user": {
        "status": 0,
        "statusTimestamp": "2019-11-05T00:00:00",
        "creation": "2019-10-30T00:00:00",
        "modification": "2019-11-05T12:00:00",
        "userId": 1,
        "name": "Administrator",
        "fullName": "系统管理员",
        "description": "系统管理员(系统内置帐号)"
    },
    "creation": "2019-11-11T00:00:59",
    "duration": "02:00:00"
}
```

<a name="other"></a>
## 其他

更多部署和运行信息请参考 [**Zongsoft.Web.Launcher**](https://github.com/Zongsoft/Zongsoft.Web.Launcher) 宿主项目文档。


最后，希望你能喜欢 _**Zongsoft**_ 面向服务的插件架构和插件化开发方式。


<a name="contribution"></a>
## 贡献

请不要在项目的 **I**ssues 中提交询问(**Q**uestion)以及咨询讨论，**I**ssue 是用来报告问题(**B**ug)和功能特性(**F**eature)。如果你希望参与贡献，欢迎提交 代码合并请求(_[**P**ull**R**equest](https://github.com/Zongsoft/Zongsoft.Security/pulls)_) 或问题反馈(_[**I**ssue](https://github.com/Zongsoft/Zongsoft.Security/issues)_)。

对于新功能，请务必创建一个功能反馈(_[**I**ssue](https://github.com/Zongsoft/Zongsoft.Security/issues)_)来详细描述你的建议，以便我们进行充分讨论，这也将使我们更好的协调工作防止重复开发，并帮助你调整建议或需求，使之成功地被接受到项目中。

欢迎你为我们的开源项目撰写文章进行推广，如果需要我们在官网(_[http://zongsoft.com/blog](http://zongsoft.com/blog)_) 中转发你的文章、博客、视频等可通过 [**电子邮件**](mailto:zongsoft@qq.com) 联系我们。

> 强烈推荐阅读 [《提问的智慧》](https://github.com/ryanhanwu/How-To-Ask-Questions-The-Smart-Way/blob/master/README-zh_CN.md)、[《如何向开源社区提问题》](https://github.com/seajs/seajs/issues/545) 和 [《如何有效地报告 Bug》](http://www.chiark.greenend.org.uk/~sgtatham/bugs-cn.html)、[《如何向开源项目提交无法解答的问题》](https://zhuanlan.zhihu.com/p/25795393)，更好的问题更容易获得帮助。


<a name="sponsor"></a>
### 支持赞助

非常期待您的支持与赞助，可以通过下面几种方式为我们提供必要的资金支持：

1. 关注 **Zongsoft 微信公众号**，对我们的文章进行打赏；
2. 加入 [**Zongsoft 知识星球号**](https://t.zsxq.com/2nyjqrr)，可以获得在线问答和技术支持；
3. 如果您的企业需要现场技术支持与辅导，又或者需要特定新功能、即刻的错误修复等请[发邮件](mailto:zongsoft@qq.com)给我。

[![微信公号](https://raw.githubusercontent.com/Zongsoft/Guidelines/master/zongsoft-qrcode%28wechat%29.png)](http://weixin.qq.com/r/zy-g_GnEWTQmrS2b93rd)

[![知识星球](https://raw.githubusercontent.com/Zongsoft/Guidelines/master/zongsoft-qrcode%28zsxq%29.png)](https://t.zsxq.com/2nyjqrr)


<a name="license"></a>
## 授权协议

本项目采用 [LGPL](https://opensource.org/licenses/LGPL-2.1) 授权协议。