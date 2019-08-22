/*
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@gmail.com>
 *
 * Copyright (C) 2017 Zongsoft Corporation <http://www.zongsoft.com>
 *
 * This file is part of Zongsoft.Security.Web.
 *
 * Zongsoft.Security.Web is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Zongsoft.Security.Web is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Zongsoft.Security.Web; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

using System;
using System.Collections.Generic;
using System.Web.Http;

using Zongsoft.Services;
using Zongsoft.Security.Membership;

namespace Zongsoft.Security.Web.Http.Controllers
{
	public class AuthenticationController : System.Web.Http.ApiController
	{
		#region 成员字段
		private IAuthenticator _authenticator;
		private ICredentialProvider _credentialProvider;
		#endregion

		#region 公共属性
		[ServiceDependency]
		public IAuthenticator Authenticator
		{
			get => _authenticator;
			set => _authenticator = value ?? throw new ArgumentNullException();
		}

		[ServiceDependency]
		public ICredentialProvider CredentialProvider
		{
			get => _credentialProvider;
			set => _credentialProvider = value ?? throw new ArgumentNullException();
		}
		#endregion

		#region 公共方法
		public Credential Post(string scene, AuthenticationRequest request)
		{
			return this.Signin(scene, request);
		}

		[HttpPost]
		public Credential Signin(string id, AuthenticationRequest request)
		{
			if(string.IsNullOrWhiteSpace(id))
				throw new HttpResponseException(System.Net.HttpStatusCode.BadRequest);

			var scene = id.Trim();
			var parameters = request.Parameters;

			//处理头部参数
			this.FillParameters(ref parameters);

			//进行身份验证
			var user = _authenticator.Authenticate(request.Identity, request.Password, request.Namespace, scene, ref parameters);

			//注册用户凭证
			var credential = _credentialProvider.Register(user, scene, parameters);

			//返回严重通过的凭证
			return credential;
		}

		[HttpGet]
		public void Signout(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				throw new HttpResponseException(System.Net.HttpStatusCode.BadRequest);

			_credentialProvider.Unregister(id);
		}
		#endregion

		#region 私有方法
		private void FillParameters(ref IDictionary<string, object> parameters)
		{
			const string X_PARAMETER_PREFIX = "x-parameter-";

			if(parameters == null)
				parameters = new Dictionary<string, object>();

			foreach(var header in this.Request.Headers)
			{
				if(header.Key.Length > X_PARAMETER_PREFIX.Length &&
				   header.Key.StartsWith(X_PARAMETER_PREFIX, StringComparison.OrdinalIgnoreCase))
				{
					parameters.Add(header.Key.Substring(X_PARAMETER_PREFIX.Length), string.Join("|", header.Value));
				}
			}
		}
		#endregion

		#region 嵌套子类
		public struct AuthenticationRequest
		{
			#region 成员字段
			private string _identity;
			private string _password;
			private string _namespace;
			#endregion

			#region 公共属性
			public string Identity
			{
				get
				{
					return _identity;
				}
				set
				{
					if(string.IsNullOrWhiteSpace(value))
						throw new ArgumentNullException();

					_identity = value.Trim();
				}
			}

			public string Password
			{
				get
				{
					return _password;
				}
				set
				{
					_password = value;
				}
			}

			public string Namespace
			{
				get
				{
					return _namespace;
				}
				set
				{
					_namespace = value;
				}
			}

			public IDictionary<string, object> Parameters
			{
				get;
				set;
			}
			#endregion
		}
		#endregion
	}
}
