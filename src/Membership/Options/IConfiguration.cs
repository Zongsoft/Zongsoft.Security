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

namespace Zongsoft.Security.Membership.Options
{
	/// <summary>
	/// 表示成员安全管理配置的接口。
	/// </summary>
	public interface IConfiguration
	{
		/// <summary>
		/// 获取或设置密码的最小长度，零表示不限制。
		/// </summary>
		int PasswordLength
		{
			get; set;
		}

		/// <summary>
		/// 获取或设置密码的强度。
		/// </summary>
		PasswordStrength PasswordStrength
		{
			get; set;
		}

		/// <summary>
		/// 获取或设置验证失败的阈值，零表示不限制。
		/// </summary>
		int AttemptThreshold
		{
			get; set;
		}

		/// <summary>
		/// 获取或设置验证失败超过指定的阈值后的锁定时长，单位：分钟。
		/// </summary>
		int AttemptWindow
		{
			get; set;
		}

		/// <summary>
		/// 获取或设置是否启用邮箱地址的有效性校验。
		/// </summary>
		bool EmailVerifyEnabled
		{
			get; set;
		}

		/// <summary>
		/// 获取或设置是否启用手机号码的有效性校验。
		/// </summary>
		bool PhoneVerifyEnabled
		{
			get; set;
		}
	}
}
