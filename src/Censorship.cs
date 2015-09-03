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
	public class Censorship : ICensorship
	{
		#region 常量定义
		private const string DATA_ENTITY_CENSORSHIP = "Security.Censorship";

		public const string KEY_NAMES = "Names";
		public const string KEY_SENSITIVES = "Sensitives";
		#endregion

		#region 成员字段
		private string[] _keys;
		private IDataAccess _dataAccess;
		#endregion

		#region 构造函数
		public Censorship()
		{
		}

		public Censorship(string[] keys)
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

		public IDataAccess DataAccess
		{
			get
			{
				return _dataAccess;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_dataAccess = value;
			}
		}
		#endregion

		#region 公共方法
		public bool IsBlocked(string word, params string[] keys)
		{
			if(string.IsNullOrWhiteSpace(word))
				return false;

			var dataAccess = this.DataAccess;

			if(dataAccess == null)
				throw new MissingMemberException(this.GetType().FullName, "DataAccess");

			return dataAccess.Count(DATA_ENTITY_CENSORSHIP,
				new ConditionCollection(ConditionCombine.And,
					new Condition("Name", keys ?? _keys, ConditionOperator.In),
					new Condition("Word", word.Trim()))) > 0;
		}
		#endregion
	}
}
