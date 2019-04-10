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

using Zongsoft.Options;
using Zongsoft.Options.Configuration;

namespace Zongsoft.Security.Membership.Options.Configuration
{
	public class GeneralConfiguration : OptionConfigurationElement, IConfiguration
	{
		#region 常量定义
		private const string XML_PASSWORDLENGTH_ATTRIBUTE = "passwordLength";
		private const string XML_PASSWORDSTRENGTH_ATTRIBUTE = "passwordStrength";
		private const string XML_ATTEMPTTHRESHOLD_ATTRIBUTE = "attemptThreshold";
		private const string XML_ATTEMPTWINDOW_ATTRIBUTE = "attemptWindow";
		private const string XML_VERIFYEMAILENABLED_ATTRIBUTE = "verifyEmailEnabled";
		private const string XML_VERIFYPHONEENABLED_ATTRIBUTE = "verifyPhoneEnabled";
		#endregion

		#region 公共属性
		[OptionConfigurationProperty(XML_PASSWORDLENGTH_ATTRIBUTE, DefaultValue = 6)]
		public int PasswordLength
		{
			get
			{
				return (int)this[XML_PASSWORDLENGTH_ATTRIBUTE];
			}
			set
			{
				this[XML_PASSWORDLENGTH_ATTRIBUTE] = value;
			}
		}

		[OptionConfigurationProperty(XML_PASSWORDSTRENGTH_ATTRIBUTE, DefaultValue = PasswordStrength.None)]
		public PasswordStrength PasswordStrength
		{
			get
			{
				return (PasswordStrength)this[XML_PASSWORDSTRENGTH_ATTRIBUTE];
			}
			set
			{
				this[XML_PASSWORDSTRENGTH_ATTRIBUTE] = value;
			}
		}

		[OptionConfigurationProperty(XML_ATTEMPTTHRESHOLD_ATTRIBUTE, DefaultValue = 3)]
		public int AttemptThreshold
		{
			get
			{
				return (int)this[XML_ATTEMPTTHRESHOLD_ATTRIBUTE];
			}
			set
			{
				this[XML_ATTEMPTTHRESHOLD_ATTRIBUTE] = value;
			}
		}

		[OptionConfigurationProperty(XML_ATTEMPTWINDOW_ATTRIBUTE, DefaultValue = 60)]
		public int AttemptWindow
		{
			get
			{
				return (int)this[XML_ATTEMPTWINDOW_ATTRIBUTE];
			}
			set
			{
				this[XML_ATTEMPTWINDOW_ATTRIBUTE] = value;
			}
		}

		[OptionConfigurationProperty(XML_VERIFYEMAILENABLED_ATTRIBUTE, DefaultValue = false)]
		public bool VerifyEmailEnabled
		{
			get
			{
				return (bool)this[XML_VERIFYEMAILENABLED_ATTRIBUTE];
			}
			set
			{
				this[XML_VERIFYEMAILENABLED_ATTRIBUTE] = value;
			}
		}

		[OptionConfigurationProperty(XML_VERIFYPHONEENABLED_ATTRIBUTE, DefaultValue = false)]
		public bool VerifyPhoneEnabled
		{
			get
			{
				return (bool)this[XML_VERIFYPHONEENABLED_ATTRIBUTE];
			}
			set
			{
				this[XML_VERIFYPHONEENABLED_ATTRIBUTE] = value;
			}
		}
		#endregion
	}
}
