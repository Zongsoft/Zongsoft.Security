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
			var user = string.IsNullOrEmpty(request.Secret) ?
				_authenticator.Authenticate(request.Identity, request.Password, request.Namespace, scene, ref parameters) :
				_authenticator.AuthenticateSecret(request.Identity, request.Secret, request.Namespace, scene, ref parameters);

			//创建用户凭证
			var credential = new Credential(user, scene, TimeSpan.FromHours(2), parameters);

			//注册用户凭证
			_credentialProvider.Register(credential);

			//返回注册的凭证
			return credential;
		}

		[HttpGet]
		[Authorization(AuthorizationMode.Identity)]
		public void Signout(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				throw new HttpResponseException(System.Net.HttpStatusCode.BadRequest);

			_credentialProvider.Unregister(id);
		}

		[HttpGet]
		[ActionName("Secret")]
		public void Secret(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				throw Zongsoft.Web.Http.HttpResponseExceptionUtility.BadRequest("Missing required argument.");

			var parts = id.Split(':');

			if(parts.Length > 1)
				_authenticator.Secret(parts[1], parts[0]);
			else
				_authenticator.Secret(parts[0], null);
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
				get; set;
			}

			public string Secret
			{
				get; set;
			}

			public string Namespace
			{
				get; set;
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
