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
using System.Collections.Generic;

using Zongsoft.Data;

namespace Zongsoft.Security
{
	public class Censorship : Zongsoft.Services.ServiceBase, ICensorship
	{
		#region 常量定义
		private const string DATA_ENTITY_CENSORSHIP = "Security.Censorship";

		public const string KEY_NAMES = "Names";
		public const string KEY_SENSITIVES = "Sensitives";
		#endregion

		#region 成员字段
		private string[] _keys;
		#endregion

		#region 构造函数
		public Censorship(Zongsoft.Services.IServiceProvider serviceProvider) : base(serviceProvider)
		{
		}

		public Censorship(Zongsoft.Services.IServiceProvider serviceProvider, params string[] keys) : base(serviceProvider)
		{
			_keys = keys;
		}
		#endregion

		#region 公共属性
		public string[] Keys
		{
			get
			{
				return _keys;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				if(value.Length < 1)
					throw new ArgumentException("The length of array is zero.");

				_keys = value;
			}
		}
		#endregion

		#region 公共方法
		public bool IsBlocked(string word, params string[] keys)
		{
			if(string.IsNullOrWhiteSpace(word))
				return false;

			//处理空键参数
			if(keys == null || keys.Length < 1)
				keys = _keys;

			var dataAccess = this.EnsureService<IDataAccess>();

			if(keys == null || keys.Length < 1)
				return dataAccess.Exists(DATA_ENTITY_CENSORSHIP, new Condition("Word", word.Trim()));

			return dataAccess.Exists(DATA_ENTITY_CENSORSHIP,
				new ConditionCollection(ConditionCombine.And,
					new Condition("Name", keys, ConditionOperator.In),
					new Condition("Word", word.Trim())));
		}
		#endregion
	}
}
