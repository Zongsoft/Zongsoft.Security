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

namespace Zongsoft.Security.Membership.Common
{
	public class UserNameValidator : IValidator<string>, IMatchable<string>
	{
		public bool Validate(string parameter, Func<string, string, bool?> failure = null)
		{
			bool? result = null;

			if(string.IsNullOrEmpty(parameter))
			{
				result = failure?.Invoke(null, "The name is null or empty.");

				if(result.HasValue)
					return result.Value;
			}

			//名字(用户名或角色名)的长度必须不少于4个字符
			if(parameter.Length < 4)
			{
				result = failure?.Invoke(null, $"The '{parameter}' name length must be greater than 3.");

				if(result.HasValue)
					return result.Value;
			}

			//名字(用户名或角色名)的首字符必须是字母、下划线、美元符
			if(!(Char.IsLetter(parameter[0]) || parameter[0] == '_' || parameter[0] == '$'))
			{
				result = failure?.Invoke(null, $"The '{parameter}' name contains illegal characters.");

				if(result.HasValue)
					return result.Value;
			}

			//检查名字(用户名或角色名)的其余字符的合法性
			for(int i = 1; i < parameter.Length; i++)
			{
				//名字的中间字符必须是字母、数字或下划线
				if(!Char.IsLetterOrDigit(parameter[i]) && parameter[i] != '_')
				{
					result = failure?.Invoke(null, $"The '{parameter}' name contains illegal characters.");

					if(result.HasValue)
						return result.Value;
				}
			}

			//通过所有检测，返回成功
			return true;
		}

		public bool IsMatch(string parameter)
		{
			return string.Equals(parameter, "Name", StringComparison.OrdinalIgnoreCase) |
			       string.Equals(parameter, "UserName", StringComparison.OrdinalIgnoreCase) |
			       string.Equals(parameter, "User.Name", StringComparison.OrdinalIgnoreCase);
		}

		bool IMatchable.IsMatch(object parameter)
		{
			return this.IsMatch(parameter as string);
		}
	}
}
