/*
 *   _____                                ______
 *  /_   /  ____  ____  ____  _________  / __/ /_
 *    / /  / __ \/ __ \/ __ \/ ___/ __ \/ /_/ __/
 *   / /__/ /_/ / / / / /_/ /\_ \/ /_/ / __/ /_
 *  /____/\____/_/ /_/\__  /____/\____/_/  \__/
 *                   /____/
 *
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@qq.com>
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
	/// <summary>
	/// 提供密码有效性验证的验证器类。
	/// </summary>
	public class PasswordValidator : IValidator<string>, IMatchable<string>
	{
		#region 常量定义
		private const int PASSWORD_STRENGTH_DIGIT = 1;
		private const int PASSWORD_STRENGTH_LOWERCASE = 2;
		private const int PASSWORD_STRENGTH_UPPERCASE = 4;
		private const int PASSWORD_STRENGTH_SYMBOL = 8;

		private const int PASSWORD_STRENGTH_LETTER = PASSWORD_STRENGTH_LOWERCASE | PASSWORD_STRENGTH_UPPERCASE;
		private const int PASSWORD_STRENGTH_LETTER_DIGIT = PASSWORD_STRENGTH_DIGIT | PASSWORD_STRENGTH_LOWERCASE | PASSWORD_STRENGTH_UPPERCASE;
		#endregion

		#region 公共属性
		public Options.IUserOption Option
		{
			get;
			set;
		}
		#endregion

		#region 验证方法
		public bool Validate(string data, Action<string> failure = null)
		{
			var option = this.Option;

			//如果没有设置密码验证策略，则返回验证成功
			if(option == null || option.PasswordLength < 1)
				return true;

			//如果如果密码长度小于配置要求的长度，则返回验证失败
			if(string.IsNullOrEmpty(data) || data.Length < option.PasswordLength)
			{
				failure?.Invoke($"The password length must be no less than {option.PasswordLength.ToString()} characters.");
				return false;
			}

			var isValidate = true;

			switch(option.PasswordStrength)
			{
				case PasswordStrength.Digits:
					isValidate = this.GetStrength(data) == PASSWORD_STRENGTH_DIGIT;

					if(!isValidate)
					{
						failure?.Invoke("The password must be digits.");
						return false;
					}

					break;
				case PasswordStrength.Lowest:
					isValidate = data != null && data.Length > 0;

					if(!isValidate)
					{
						failure?.Invoke("The password cannot be empty.");
						return false;
					}

					break;
				case PasswordStrength.Normal:
					var strength = this.GetStrength(data);

					isValidate = strength == (PASSWORD_STRENGTH_DIGIT + PASSWORD_STRENGTH_LOWERCASE) ||
					             strength == (PASSWORD_STRENGTH_DIGIT + PASSWORD_STRENGTH_UPPERCASE);

					if(!isValidate)
					{
						failure?.Invoke("");
						return false;
					}

					break;
				case PasswordStrength.Highest:
					isValidate = this.GetStrength(data) == PASSWORD_STRENGTH_DIGIT +
					                                       PASSWORD_STRENGTH_SYMBOL +
					                                       PASSWORD_STRENGTH_LOWERCASE +
					                                       PASSWORD_STRENGTH_UPPERCASE;

					if(!isValidate)
					{
						failure?.Invoke("");
						return false;
					}

					break;
			}

			//返回密码有效性验证成功
			return true;
		}
		#endregion

		#region 匹配方法
		public bool IsMatch(string parameter)
		{
			return string.Equals(parameter, "Password", StringComparison.OrdinalIgnoreCase) |
				   string.Equals(parameter, "User.Password", StringComparison.OrdinalIgnoreCase);
		}

		bool IMatchable.IsMatch(object parameter)
		{
			return this.IsMatch(parameter as string);
		}
		#endregion

		#region 私有方法
		private int GetStrength(string data)
		{
			int flag = 0;

			for(int i = 0; i < data.Length; i++)
			{
				var chr = data[i];

				if(chr >= '0' && chr <= '9')
					flag |= PASSWORD_STRENGTH_DIGIT;
				else if(chr >= 'a' && chr <= 'z')
					flag |= PASSWORD_STRENGTH_LOWERCASE;
				else if(chr >= 'A' && chr <= 'Z')
					flag |= PASSWORD_STRENGTH_UPPERCASE;
				else
					flag |= PASSWORD_STRENGTH_SYMBOL;
			}

			return flag;
		}
		#endregion
	}
}
