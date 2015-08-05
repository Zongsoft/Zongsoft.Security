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
using System.ComponentModel;

namespace Zongsoft.Security.Commands
{
	[Serializable]
	public class Authenticode
	{
		#region 成员字段
		private string _source;
		private string _destination;
		private string _value;
		#endregion

		#region 构造函数
		public Authenticode()
		{
		}

		public Authenticode(string source, string destination, string value)
		{
			if(string.IsNullOrWhiteSpace(source))
				throw new ArgumentNullException("source");

			if(string.IsNullOrWhiteSpace(destination))
				throw new ArgumentNullException("destination");

			if(string.IsNullOrWhiteSpace(value))
				throw new ArgumentNullException("value");

			_source = source.Trim();
			_destination = destination.Trim();
			_value = value.Trim();
		}
		#endregion

		#region 公共属性
		public string Source
		{
			get
			{
				return _source;
			}
			set
			{
				if(string.IsNullOrWhiteSpace(value))
					throw new ArgumentNullException();

				_source = value.Trim();
			}
		}

		public string Destination
		{
			get
			{
				return _destination;
			}
			set
			{
				if(string.IsNullOrWhiteSpace(value))
					throw new ArgumentNullException();

				_destination = value.Trim();
			}
		}

		public string Value
		{
			get
			{
				return _value;
			}
			set
			{
				if(string.IsNullOrWhiteSpace(value))
					throw new ArgumentNullException();

				_value = value.Trim();
			}
		}
		#endregion
	}
}
