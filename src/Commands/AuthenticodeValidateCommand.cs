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

using Zongsoft.Services;
using Zongsoft.Runtime.Caching;

namespace Zongsoft.Security.Commands
{
	public class AuthenticodeValidateCommand : CommandBase<CommandContext>
	{
		#region 成员字段
		private ICache _cache;
		#endregion

		#region 构造函数
		public AuthenticodeValidateCommand() : base("validate")
		{
		}
		#endregion

		#region 公共属性
		/// <summary>
		/// 获取或设置验证码验证命令依赖的缓存容器。
		/// </summary>
		public ICache Cache
		{
			get
			{
				return _cache;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_cache = value;
			}
		}
		#endregion

		#region 重写方法
		protected override void OnExecute(CommandContext context)
		{
			if(context.Arguments.Length < 3)
				throw new CommandException(Zongsoft.Resources.ResourceUtility.GetString("Text.MissingCommandArguments"));

			var cache = this.Cache;

			if(cache == null)
				throw new MissingMemberException(this.GetType().FullName, "Cache");

			var text = (string)cache.GetValue(AuthenticodeSendCommand.GetStorageKey(context.Arguments[0], context.Arguments[1]));

			if(string.IsNullOrWhiteSpace(text))
			{
				context.Result = false;
				return;
			}

			var entity = Zongsoft.Runtime.Serialization.Serializer.Json.Deserialize<Authenticode>(text);
			context.Result = entity != null && string.Equals(entity.Value, context.Arguments[2], StringComparison.OrdinalIgnoreCase);
		}
		#endregion
	}
}
