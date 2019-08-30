﻿/*
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
 * Copyright (C) 2015-2019 Zongsoft Corporation <http://www.zongsoft.com>
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

using Zongsoft.Options;
using Zongsoft.Options.Configuration;

namespace Zongsoft.Security.Membership.Options.Configuration
{
	public class AuthenticationOption : OptionConfigurationElement, IAuthenticationOption
	{
		#region 常量定义
		private const string XML_ATTEMPTER_ELEMENT = "attempter";
		private const string XML_CREDENTIAL_ELEMENT = "credential";
		#endregion

		#region 公共属性
		[OptionConfigurationProperty(XML_ATTEMPTER_ELEMENT, typeof(AttempterOption))]
		public IAttempterOption Attempter
		{
			get => (AttempterOption)this[XML_ATTEMPTER_ELEMENT];
		}

		[OptionConfigurationProperty(XML_CREDENTIAL_ELEMENT, typeof(CredentialOption))]
		public ICredentialOption Credential
		{
			get => (ICredentialOption)this[XML_CREDENTIAL_ELEMENT];
		}
		#endregion

		#region 嵌套子类
		public class AttempterOption : OptionConfigurationElement, IAttempterOption
		{
			#region 常量定义
			private const string XML_THRESHOLD_ATTRIBUTE = "threshold";
			private const string XML_WINDOW_ATTRIBUTE = "window";
			#endregion

			#region 公共属性
			[OptionConfigurationProperty(XML_THRESHOLD_ATTRIBUTE, DefaultValue = 3)]
			public int Threshold
			{
				get => (int)this[XML_THRESHOLD_ATTRIBUTE];
				set => this[XML_THRESHOLD_ATTRIBUTE] = value;
			}

			[OptionConfigurationProperty(XML_WINDOW_ATTRIBUTE, DefaultValue = "1:0:0")]
			public TimeSpan Window
			{
				get => (TimeSpan)this[XML_WINDOW_ATTRIBUTE];
				set => this[XML_WINDOW_ATTRIBUTE] = value;
			}
			#endregion
		}
		#endregion
	}
}
