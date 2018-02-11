/*
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@gmail.com>
 *
 * Copyright (C) 2010-2018 Zongsoft Corporation <http://www.zongsoft.com>
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

using Zongsoft.Data;
using Zongsoft.Collections;
using Zongsoft.Services;

namespace Zongsoft.Security.Membership.Common
{
	public class UserPhoneVerifier : SecretVerifierBase, IMatchable<string>
	{
		#region 成员字段
		private IDataAccess _dataAccess;
		#endregion

		#region 构造函数
		public UserPhoneVerifier(IDataAccess dataAccess) : base("zongsoft.security")
		{
			_dataAccess = dataAccess;
		}
		#endregion

		#region 公共属性
		[ServiceDependency]
		public IDataAccess DataAccess
		{
			get
			{
				return _dataAccess;
			}
			set
			{
				_dataAccess = value ?? throw new ArgumentNullException();
			}
		}
		#endregion

		#region 重写方法
		protected override void OnSucceed(string name, object value, object state)
		{
			int index = -1;
			var phone = value as string;

			if(phone != null && phone.Length > 0)
			{
				index = phone.IndexOf('|');

				if(index > 0 && index < phone.Length - 1)
					phone = phone.Substring(index + 1);
				else
					phone = null;
			}

			if(index >= 0)
			{
				_dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
					new
					{
						PhoneNumber = string.IsNullOrEmpty(phone) ? null : phone.Trim(),
						ModifiedTime = DateTime.Now,
					}, Condition.Equal("UserId", state));
			}

			//调用基类同名方法
			base.OnSucceed(name, value, state);
		}
		#endregion

		#region 模式匹配
		public bool IsMatch(string parameter)
		{
			return string.Equals(parameter, "phone", StringComparison.OrdinalIgnoreCase) |
				   string.Equals(parameter, "user.phone", StringComparison.OrdinalIgnoreCase);
		}

		bool IMatchable.IsMatch(object parameter)
		{
			return this.IsMatch(parameter as string);
		}
		#endregion
	}
}
