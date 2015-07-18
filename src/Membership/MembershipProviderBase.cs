/*
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@gmail.com>
 *
 * Copyright (C) 2015 Zongsoft Corporation <http://www.zongsoft.com>
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
using Zongsoft.Options;

namespace Zongsoft.Security.Membership
{
	public class MembershipProviderBase : MarshalByRefObject
	{
		#region 成员字段
		private IDataAccess _dataAccess;
		#endregion

		#region 构造函数
		protected MembershipProviderBase()
		{
		}
		#endregion

		#region 公共属性
		public IDataAccess DataAccess
		{
			get
			{
				return _dataAccess;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_dataAccess = value;
			}
		}
		#endregion

		#region 保护方法
		protected IDataAccess EnsureDataAccess()
		{
			if(_dataAccess == null)
				throw new InvalidOperationException("The value of 'DataAccess' property is null.");

			return _dataAccess;
		}
		#endregion
	}
}
