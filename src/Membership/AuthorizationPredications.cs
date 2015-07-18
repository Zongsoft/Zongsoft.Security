﻿/*
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@gmail.com>
 *
 * Copyright (C) 2010-2015 Zongsoft Corporation <http://www.zongsoft.com>
 *
 * This file is part of Zongsoft.Security.
 *
 * Zongsoft.Security is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Zongsoft.Security is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Zongsoft.Security; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Zongsoft.Security.Membership
{
	public class AuthorizationPredicationBase : Zongsoft.Services.IMatchable<string>
	{
		#region 静态字段
		private static readonly Regex _regex = new Regex(@"[^,\s]+", (RegexOptions.Compiled | RegexOptions.IgnorePatternWhitespace | RegexOptions.ExplicitCapture));
		#endregion

		#region 成员字段
		private string _name;
		private IAuthorization _authorization;
		private Zongsoft.ComponentModel.ApplicationContextBase _applicationContext;
		#endregion

		#region 构造函数
		protected AuthorizationPredicationBase(string name, Zongsoft.ComponentModel.ApplicationContextBase applicationContext)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new ArgumentNullException("name");

			if(applicationContext == null)
				throw new ArgumentNullException("applicationContext");

			_name = name.Trim();
			_applicationContext = applicationContext;
		}
		#endregion

		#region 公共属性
		public string Name
		{
			get;
			private set;
		}

		public IAuthorization Authorization
		{
			get
			{
				if(_authorization == null)
				{
					var serviceProvider = _applicationContext.ServiceFactory.GetProvider("Security") ?? _applicationContext.ServiceFactory.Default;

					if(serviceProvider != null)
						_authorization = serviceProvider.Resolve<IAuthorization>();
				}

				return _authorization;
			}
			set
			{
				_authorization = value;
			}
		}
		#endregion

		#region 保护方法
		protected bool IsAuthorized(string text)
		{
			var authorization = this.Authorization;

			if(authorization == null)
				throw new MissingMemberException(this.GetType().FullName, "Authorization");

			var principal = _applicationContext.Principal as Zongsoft.Security.CertificationPrincipal;

			if(principal == null || principal.Identity == null || (!principal.Identity.IsAuthenticated) || principal.Identity.Certification == null || principal.Identity.Certification.User == null)
				return false;

			var matches = _regex.Matches(text);

			if(matches.Count != 2)
				return false;

			return authorization.IsAuthorized(principal.Identity.Certification.User.UserId, matches[0].Value, matches[1].Value);
		}
		#endregion

		#region 服务匹配
		public bool IsMatch(string parameter)
		{
			return string.Equals(parameter, this.Name, StringComparison.OrdinalIgnoreCase);
		}

		bool Zongsoft.Services.IMatchable.IsMatch(object parameter)
		{
			return this.IsMatch(parameter as string);
		}
		#endregion
	}

	public class IsAuthorizedPredication : AuthorizationPredicationBase, Zongsoft.Services.IPredication<string>
	{
		#region 构造函数
		public IsAuthorizedPredication(string name, Zongsoft.ComponentModel.ApplicationContextBase applicationContext)
			: base(name, applicationContext)
		{
		}
		#endregion

		#region 断言方法
		public bool Predicate(string parameter)
		{
			if(string.IsNullOrWhiteSpace(parameter))
				return false;

			return this.IsAuthorized(parameter);
		}

		bool Zongsoft.Services.IPredication.Predicate(object parameter)
		{
			return this.Predicate(parameter as string);
		}
		#endregion
	}

	public class IsUnauthorizedPredication : AuthorizationPredicationBase, Zongsoft.Services.IPredication<string>
	{
		#region 构造函数
		public IsUnauthorizedPredication(string name, Zongsoft.ComponentModel.ApplicationContextBase applicationContext)
			: base(name, applicationContext)
		{
		}
		#endregion

		#region 断言方法
		public bool Predicate(string parameter)
		{
			if(string.IsNullOrWhiteSpace(parameter))
				return false;

			return !this.IsAuthorized(parameter);
		}

		bool Zongsoft.Services.IPredication.Predicate(object parameter)
		{
			return this.Predicate(parameter as string);
		}
		#endregion
	}
}