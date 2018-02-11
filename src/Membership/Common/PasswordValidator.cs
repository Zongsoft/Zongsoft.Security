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
	public class PasswordValidator : IValidator<string>, IMatchable<string>
	{
		public bool Validate(string data, Func<string, string, bool?> failure = null)
		{
			return true;
		}

		public bool IsMatch(string parameter)
		{
			return string.Equals(parameter, "Password", StringComparison.OrdinalIgnoreCase) |
				   string.Equals(parameter, "User.Password", StringComparison.OrdinalIgnoreCase);
		}

		bool IMatchable.IsMatch(object parameter)
		{
			return this.IsMatch(parameter as string);
		}
	}
}
