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
	public class CredentialOption : OptionConfigurationElement, ICredentialOption
	{
		#region 常量定义
		private const string XML_PERIOD_ATTRIBUTE = "period";
		private const string XML_POLICIES_COLLECTION = "policies";
		#endregion

		#region 公共属性
		[OptionConfigurationProperty(XML_PERIOD_ATTRIBUTE, OptionConfigurationPropertyBehavior.IsRequired)]
		public TimeSpan Period
		{
			get => (TimeSpan)this[XML_PERIOD_ATTRIBUTE];
			set => this[XML_PERIOD_ATTRIBUTE] = value;
		}

		[OptionConfigurationProperty(XML_POLICIES_COLLECTION, typeof(CredentialPolicyCollection))]
		public Collections.INamedCollection<ICredentialPolicy> Policies
		{
			get
			{
				return (Collections.INamedCollection<ICredentialPolicy>)this[XML_POLICIES_COLLECTION];
			}
		}
		#endregion
	}
}
