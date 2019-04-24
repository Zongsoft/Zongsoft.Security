# Zongsoft.Security 安全管理 API 接口手册

[TOC]

## API 公共参数

### 所有 Web API 都支持以下 HTTP-Headers：

1. 响应JSON实体中属性字段的命名转换规则 `x-json-casing`
	> - `none` 无要求，采用服务端原本命名规则。
	> - `camel` 小驼峰命名规则，即首字符小写。
	> - `pascal` 大驼峰命名规则，即每个单词的首字母都大写。

2. 响应JSON实体中日期时间值的格式 `x-json-datetime`
   > 指定的日期格式模式字符串，譬如：`yyyy-MM-dd HH:mm:ss`。

3. 响应JSON实体的其他行为方式 `x-json-behaviors`
	> 多个行为指令以逗号（`,`）或分号（`;`）分隔，以下为目前支持的行为指令：
	> - `indented` 表示以缩进的方式格式化返回的JSON实体。
	> - `ignores:none` 表示不忽略任何实体成员，默认值。
	> - `ignores:null` 表示忽略实体中值为空的成员。
	> 譬如忽略实体中所有为空的成员并且以缩进方式格式化JSON实体的 `x-json-behaviors` 头部内容为：`ignores:null,indented`

-----

**注意：** 通过登录接口成功即可获得凭证对象，后续的 API 调用中都必须通过 HTTP `Authorization` 头来指定凭证号以标识对应的授权主体，该验证头的内容为：`Credential {credentialId}`，其中 `{credentialId}` 即为具体的凭证号。

-----

## 登录接口
```url
[POST] /Security/Authentication/Signin/{scene}
```

### 参数说明

- scene
  > 应用场景，为了避免相同账号登录导致的互斥而指定的场景标识。譬如：
  > - `web` 网页端；
  > - `mobile` 移动端;
  > - `wechat` 微信端。

### 请求参数

```json
{
	Identity:"UserName|PhoneNumber|Email",
	Password:"******",
	Namespace:"",
	Parameters:{}
}
```

#### 字段说明

- `Identity` 字段：必选项，表示登录账号名称（用户名）或手机号、邮箱地址这三种用户标识。
- `Password` 字段：必选项，表示用户的登录密码。
- `Namespace` 字段：可选项，表示用户所属命名空间，不同业务系统对该字段的定义可能存在差异，通常在 SaaS 系统中，该字段表示租户代号。
- `Parameters` 字段：可选项，表示业务系统中需要传入的额外附加参数，该JSON实体将以键值对的方式保存在凭证中。

### 响应消息
```json
{
    "CredentialId": "0123456789ABCDEFG",
    "Scene": "web",
    "Timestamp": "2018-11-11T00:00:00",
    "IssuedTime": "2018-11-11T00:00:00",
    "Duration": "02:00:00",
    "ExtendedProperties": {},
    "User": {
        "UserId": 100,
        "Name": "Popeye",
        "FullName": "钟少",
        "Namespace": "Zongsoft",
        "Description": "",
        "Avatar": "https://files.zongsoft.com/user-100/avatar.png",
        "Principal": {},
        "PrincipalId": "1",
        "Email": null,
        "PhoneNumber": null,
        "Status": 0,
        "StatusTimestamp": null,
        "CreatorId": null,
        "CreatedTime": "2015-03-23T10:00:00",
        "ModifierId": null,
        "ModifiedTime": null,
        "Creator": null,
        "Modifier": null
    }
}
```

-----

## 注销接口
```url
[GET] /Security/Authentication/Signout/{credentialId}
```

### 参数说明
- credentialId 表示凭证编号。

-----

## 获取凭证

根据指定的凭证号或者根据指定的用户编号及场景获取对应的凭证对象。

```url
[GET] /Security/Credential/{credentialId}
[GET] /Security/Credential/{userId}-{scene}
```

### 响应消息
成功的响应消息内容同“登录接口”的响应消息。

-----

## 续约凭证

根据指定的凭证号重新续约。

```url
[GET] /Security/Credential/Renew/{credentialId}
```

### 响应消息
成功的响应消息内容同“登录接口”的响应消息。

-----

## 获取用户信息
```url
[GET] /Security/User/{pattern}
```

### 参数说明
pattern 可选项，如果该参数为纯数字则会被当做为用户编号，否则为下列定义：

- **空：** 表示查询命名空间（`Namespace`）为空(`null`)的所有用户。
- **星号：** 表示查询所有用户，即忽略命名空间，譬如：`/Security/User/*`。
- **数字：** 表示查询指定的用户编号（整型数）。
- **用户名：** 以字母打头的字符串（只能包含字母和数字），表示查询指定的用户名并且命名空间为空的用户。
- **手机号：** 数字并以惊叹号标识，譬如：`13812345678!phone`，表示查询指定手机号并且命名空间为空的用户。
- **邮箱地址：** 符合 Email 格式规范的字符串，譬如：`popeye@zongsoft.com`，表示查询指定邮箱地址并且命名空间为空的用户。
- **命名空间:`*`：** 表示查询指定命名空间中的所有用户，譬如：`zongsoft:*`。
- **命名空间:用户名** 表示查询指定命名空间和用户名的某个用户，譬如：`zongsoft:popeye`。
- **命名空间:手机号** 表示查询指定命名空间和手机号的某个用户，譬如：`zongsoft:13812345678`。
- **命名空间:邮箱地址** 表示查询指定命名空间和邮箱地址的某个用户，譬如：`zongsoft:bill@microsoft.com`。

### 响应消息
根据参数类型，返回单个用户实体或多个用户实体，具体用户实体定义请参考“表结构设计”相关文档。

-----

## 删除用户
```url
[DELETE] /Security/User/{ids}
```

### 参数说明
- ids 指定的要删除的单个或多个用户编号（多个用户编号以逗号分隔）。

-----

## 新增用户
```url
[POST] /Security/User
```

### 参数说明
可以通过名为 `x-password` 的 HTTP 头来定义新增用户的密码，如果未指定该扩展头，则由系统生成特定密码或空密码。

### 请求消息
```json
{
	Name:"",
	FullName:"",
	Namespace:"",
	Avatar:"",
	Email:"",
	PhoneNumber:"",
	PrincipalId:"",
	Description:""
}
```

#### 字段说明
除了 `Name` 字段（属性）以外都是可选字段。

### 响应消息
返回新增成功的用户实体，具体用户实体定义请参考“表结构设计”相关文档。

-----

## 修改用户
```url
[PUT] /Security/User
```

### 请求消息
```json
{
	UserId:100,
	...
}
```

要修改的用户实体（必须含“用户编号”成员），只需要包含要修改的成员，而不要包含那些没有改动或不需要修改的成员（以免不必要的覆写导致的脏写）。

-----

## 修改用户特定属性值
```url
[PATCH] /Security/User/{userId}/Name/{value}
[PATCH] /Security/User/{userId}/FullName/{value}
[PATCH] /Security/User/{userId}/Namespace/{value}
[PATCH] /Security/User/{userId}/PrincipalId/{value}
[PATCH] /Security/User/{userId}/Avatar/{value}
[PATCH] /Security/User/{userId}/Email/{value}
[PATCH] /Security/User/{userId}/PhoneNumber/{value}
[PATCH] /Security/User/{userId}/Status/{value}
[PATCH] /Security/User/{userId}/Description/{value}
```

### 参数说明
- userId 表示要修改的用户编号；
- value 表示要修改的用户的新属性值。

-----

## 判断用户是否存在

**注意：** 该接口支持匿名调用，即不需要提供 `Authorization` 验证头。

```url
[GET] /Security/User/Exists/{pattern}
```

### 参数说明
pattern 必须项，如果该参数为纯数字则会被当做为用户编号，其定义等同于“用户查询”接口中该参数。

-----

## 校验验证码

**注意：** 该接口支持匿名调用，即不需要提供 `Authorization` 验证头。

```url
[GET] /Security/User/{userId}/Verify?type=xxx&secret=xxx
```

### 参数说明
- userId 必须项，指定要校验的用户编号。
- type 必须项，表示校验的类型，由业务方定义，譬如：`forget-password`、`register` 等。
- secret 必须项，表示要校验的秘密值，通常为通过手机短信或电子邮件收到的一个随机数验证码。

-----

## 判断用户是否有密码

```url
[GET] /Security/User/Password/{pattern}
```

### 参数说明
pattern 必须项，如果该参数为纯数字则会被当做为用户编号，其定义等同于“用户查询”接口中该参数。

-----

## 修改用户密码
```url
[PUT] /Security/User/{userId}/Password
```

### 请求消息
```json
{
	OldPassword:"",
	NewPassword:""
}
```

-----

## 忘记用户密码

该方法会根据参数类型，通过相应的通道（手机短信或电子邮件）发送一个验证码到对应的手机或邮箱中。

```url
[POST] /Security/User/Password/{phoneNumber}/Forget
[POST] /Security/User/Password/{namespace}:{phoneNumber}/Forget
[POST] /Security/User/Password/{email}/Forget
[POST] /Security/User/Password/{namespace}:{email}/Forget
```

### 参数说明
- phoneNumber 表示通过手机短信的方式获取验证码，之后即可通过该验证码重置密码；
- email 表示通过电子邮件的方式获取验证码，之后即可通过该验证码重置密码；
- namespace 可选参数，表示手机号或邮箱地址所属的命名空间。

-----

## 重置用户密码（验证码）

该方法会根据参数类型，通过相应的通道（手机短信或电子邮件）发送一个验证码到对应的手机或邮箱中。

```url
[POST] /Security/User/{userId}/Password/Reset
```

### 参数说明
- userId 指定要重置的用户编号。

### 请求消息
```json
{
	Secret:"",
	Password:""
}
```

#### 字段说明
- secret 通过手机短信或电子邮件获取到的验证码；
- password 要重置的新密码。


-----

## 重置用户密码（密码问答）

该方法会根据参数类型，通过相应的通道（手机短信或电子邮件）发送一个验证码到对应的手机或邮箱中。

```url
[POST] /Security/User/{phoneNumber}/Password/Reset
[POST] /Security/User/{namespace}:{phoneNumber}/Password/Reset
[POST] /Security/User/{email}/Password/Reset
[POST] /Security/User/{namespace}:{email}/Password/Reset
```

### 参数说明
- phoneNumber 表示要重置密码的用户手机号；
- email 表示要重置密码的用户邮箱地址；
- namespace 可选参数，表示手机号或邮箱地址所属的命名空间。

### 请求消息
```json
{
	Password:"",
	PasswordAnswers:["answer1", "answer2", "answer3"]
}
```

#### 字段说明
- passwordAnswers 用户信息中密码问答中的三个答案值（必须按设置中的顺序）。
- password 要重置的新密码。


-----

## 获取用户密码问题题面

**注意：** 该接口支持匿名调用，即不需要提供 `Authorization` 验证头。

```url
[GET] /Security/User/{pattern}/PasswordQuestions
```

### 参数说明
pattern 必须项，如果该参数为纯数字则会被当做为用户编号，其定义等同于“用户查询”接口中该参数。

### 返回消息
```json
["question1", "question2", "question3"]
```

-----

## 设置用户密码问题

```url
[PUT] /Security/User/{userId}/PasswordAnswers
```

### 参数说明
userId 必须项，要设置的用户编号。

### 请求消息
```json
{
	Password:"",
	Questions:["", "", ""],
	Answers:["", "", ""]
}
```

#### 字段说明
- password 指定的用户编号参数对应的用户密码，因为要设置密码问答必须先验证指定用户的密码。
- questions 要更新的密码问答的三个题面（注意：与答案顺序一致）。
- answers 要更新的密码问答的三个答案（注意：与题面顺序一致）。

-----

## 获取用户父角色集

获取指定用户所属的父级角色集。

```url
[GET] /Security/User/{userId}/Roles
```

### 参数说明
userId 必须项，要获取的用户编号。

### 响应消息
返回多个角色实体，具体角色实体定义请参考“表结构设计”相关文档。

-----

## 判断指定的用户是否属于指定角色

```url
[GET] /Security/User/{userId}/In/{roleId}
```

### 参数说明
userId 必须项，要判断的用户编号。
roleId 必须项，要判断的角色编号。

### 响应消息
如果属于则响应状态码为204，否则状态码为404。


-----

## 授权判断

判断指定的用户是否对于具有操作指定目标的授权。

```url
[GET] /Security/User/{userId}/Authorize/{schemaId}-{actionId}
```

### 参数说明
userId 必须项，要判断的用户编号。
schemaId 必须项，要判断的目标代号。
actionId 必须项，要判断的操作代号。

### 响应消息
如果具有授权则响应状态码为204，否则状态码为404。

-----

## 获取授权状态集

获取指定用户具有授权的状态清单。

```url
[GET] /Security/User/{userId}/Authorizes
```

### 参数说明
userId 必须项，要获取的用户编号。

### 响应消息
```json
[
	{
		SchemaId:"",
		ActionId:""
	}
]
```

-----

## 获取权限设置集

获取指定用户的权限设置集。

```url
[GET] /Security/User/{userId}/Permissions/{schemaId}
```

### 参数说明
userId 必须项，要获取的用户编号。
schemaId 可选项，要获取的目标编号，如果未指定则获取所有目标授权对象。

### 响应消息
```json
[
	{
		SchemaId:"",
		ActionId:""
		Granted:true
	},
	{
		SchemaId:"",
		ActionId:""
		Granted:false
	}
]
```

-----

## 设置权限设置集

设置指定用户的权限设置集。

```url
[POST] /Security/User/{userId}/Permissions/{schemaId}
```

### 参数说明
userId 必须项，要设置的用户编号。
schemaId 必须项，要设置的目标编号。

### 请求消息
```json
[
	{
		SchemaId:"",
		ActionId:""
		Granted:true
	},
	{
		SchemaId:"",
		ActionId:""
		Granted:false
	}
]
```

