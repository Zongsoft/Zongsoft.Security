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

using Zongsoft.Common;
using Zongsoft.Collections;
using Zongsoft.Services;

namespace Zongsoft.Security.Membership.Common
{
	public class UserPhoneNotifier : SecretNotifierBase, IMatchable<string>
	{
		#region 构造函数
		public UserPhoneNotifier() : base("zongsoft.security")
		{
		}
		#endregion

		#region 重写方法
		protected override IExecutionResult OnNotify(string name, object content, object destination, string secret)
		{
			var parameter = new Dictionary<string, object>
			{
				{ "UserId", content },
				{ "Secret", secret },
			};

			return CommandExecutor.Default.Execute($"sms.send -template:{name} {destination}", parameter) as IExecutionResult;
		}
		#endregion

		#region 重写方法
		protected override string GetCacheKey(string name, object content, object destination)
		{
			var key = base.GetCacheKey(name, content, destination);

			if(content is User user)
				key += ":" + user.UserId;
			else if(content is uint id)
				key += ":" + id.ToString();
			else if(content is IDictionary<string, object> dic)
				key += ":" + dic["UserId"].ToString();

			return key;
		}
		#endregion

		#region 模式匹配
		public bool IsMatch(string parameter)
		{
			if(string.IsNullOrEmpty(parameter))
				return false;

			return parameter.EndsWith("phone", StringComparison.OrdinalIgnoreCase);
		}

		bool IMatchable.IsMatch(object parameter)
		{
			return this.IsMatch(parameter as string);
		}
		#endregion
	}
}
