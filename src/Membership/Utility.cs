/*
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@gmail.com>
 *
 * Copyright (C) 2010-2017 Zongsoft Corporation <http://www.zongsoft.com>
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
	internal static class Utility
	{
		/// <summary>
		/// 验证名字（用户名或角色名）的合法性。
		/// </summary>
		/// <param name="name">指定的名字。</param>
		public static void VerifyName(string name)
		{
			if(string.IsNullOrEmpty(name))
				throw new ArgumentNullException(nameof(name));

			//名字(用户名或角色名)的长度必须不少于4个字符
			if(name.Length < 4)
				throw new ArgumentOutOfRangeException($"The '{name}' name length must be greater than 3.");

			//名字(用户名或角色名)的首字符必须是字母、下划线、美元符
			if(!(Char.IsLetter(name[0]) || name[0] == '_' || name[0] == '$'))
				throw new ArgumentException($"The '{name}' name contains illegal characters.");

			//检查名字(用户名或角色名)的其余字符的合法性
			for(int i = 1; i < name.Length; i++)
			{
				//名字的中间字符必须是字母、数字或下划线
				if(!Char.IsLetterOrDigit(name[i]) && name[i] != '_')
					throw new ArgumentException($"The '{name}' name contains illegal characters.");
			}

		}
	}
}
