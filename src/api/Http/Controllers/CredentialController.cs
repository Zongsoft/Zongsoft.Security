﻿/*
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
using System.Net.Http;
using System.Web.Http;

using Zongsoft.Services;
using Zongsoft.Security.Membership;

namespace Zongsoft.Security.Web.Http.Controllers
{
	[Authorization(AuthorizationMode.Identity)]
	public class CredentialController : System.Web.Http.ApiController
	{
		#region 成员字段
		private ICredentialProvider _credentialProvider;
		#endregion

		#region 公共属性
		[ServiceDependency]
		public ICredentialProvider CredentialProvider
		{
			get
			{
				return _credentialProvider;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_credentialProvider = value;
			}
		}
		#endregion

		#region 公共方法
		public object Get(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				throw new HttpResponseException(System.Net.HttpStatusCode.BadRequest);

			var index = id.IndexOf('!');
			Credential credential = null;

			if(index > 0 && index < id.Length - 1)
				credential = this.CredentialProvider.GetCredential(id.Substring(0, index), id.Substring(index + 1));
			else
				credential = this.CredentialProvider.GetCredential(id);

			if(credential == null)
				return new HttpResponseMessage(System.Net.HttpStatusCode.NoContent);

			return credential;
		}

		[HttpGet]
		public object Renew(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				throw new HttpResponseException(System.Net.HttpStatusCode.BadRequest);

			var credential = this.CredentialProvider.Renew(id);

			if(credential == null)
				return new HttpResponseMessage(System.Net.HttpStatusCode.NoContent);

			return credential;
		}
		#endregion
	}
}
