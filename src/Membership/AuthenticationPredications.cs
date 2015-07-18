/*
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

namespace Zongsoft.Security.Membership
{
	public class IsAuthenticatedPredication : Zongsoft.Services.PredicationBase<object>
	{
		#region 成员字段
		private Zongsoft.ComponentModel.ApplicationContextBase _applicationContext;
		#endregion

		#region 构造函数
		public IsAuthenticatedPredication(string name, Zongsoft.ComponentModel.ApplicationContextBase applicationContext) : base(name)
		{
			if(applicationContext == null)
				throw new ArgumentNullException("applicationContext");

			_applicationContext = applicationContext;
		}
		#endregion

		#region 断言方法
		public override bool Predicate(object parameter)
		{
			var principal = _applicationContext.Principal;
			return principal != null && principal.Identity != null && principal.Identity.IsAuthenticated;
		}
		#endregion
	}

	public class IsUnauthenticatedPredication : Zongsoft.Services.PredicationBase<object>
	{
		#region 成员字段
		private Zongsoft.ComponentModel.ApplicationContextBase _applicationContext;
		#endregion

		#region 构造函数
		public IsUnauthenticatedPredication(string name, Zongsoft.ComponentModel.ApplicationContextBase applicationContext) : base(name)
		{
			if(applicationContext == null)
				throw new ArgumentNullException("applicationContext");

			_applicationContext = applicationContext;
		}
		#endregion

		#region 断言方法
		public override bool Predicate(object parameter)
		{
			var principal = _applicationContext.Principal;
			return !(principal != null && principal.Identity != null && principal.Identity.IsAuthenticated);
		}
		#endregion
	}
}
