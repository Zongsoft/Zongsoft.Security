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
using Zongsoft.Messaging;
using Zongsoft.Runtime.Caching;

namespace Zongsoft.Security.Commands
{
	[CommandOption("length", Type = typeof(int), DefaultValue = 6)]
	[CommandOption("duration", Type = typeof(int), DefaultValue = 1800)]
	public class AuthenticodeSendCommand : CommandBase<CommandContext>
	{
		#region 成员字段
		private int _period;
		private ICache _cache;
		private Zongsoft.Collections.IQueueProvider _queueProvider;
		#endregion

		#region 构造函数
		public AuthenticodeSendCommand() : base("send")
		{
			_period = 90;
		}
		#endregion

		#region 公共属性
		/// <summary>
		/// 获取或设置验证码的发送最小间隔时长，单位为秒。默认为90秒。
		/// </summary>
		public int Period
		{
			get
			{
				return _period;
			}
			set
			{
				_period = value;
			}
		}

		/// <summary>
		/// 获取或设置验证码发送命令依赖的缓存容器。
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

		/// <summary>
		/// 获取或设置验证码发送命令的目标队列的提供程序。
		/// </summary>
		public Zongsoft.Collections.IQueueProvider QueueProvider
		{
			get
			{
				return _queueProvider;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_queueProvider = value;
			}
		}
		#endregion

		#region 重写方法
		protected override void OnExecute(CommandContext context)
		{
			if(context.Arguments.Length < 2)
				throw new CommandException(Zongsoft.Resources.ResourceUtility.GetString("Text.MissingCommandArguments"));

			var cache = this.Cache;

			if(cache == null)
				throw new MissingMemberException(this.GetType().FullName, "Cache");

			var queueProvder = this.QueueProvider;

			if(queueProvder == null)
				throw new MissingMemberException(this.GetType().FullName, "QueueProvider");

			var code = GenerateCode((int)context.Options["length"]);
			var json = string.Format("{{Type:\"Authenticode\", Source:\"{0}\", Destination:\"{1}\", Value:\"{3}\"}}", context.Arguments[0], context.Arguments[1], code);
			DateTime timestamp = DateTime.Now;

			if(cache.SetValue(GetStorageKey(context.Arguments[0], context.Arguments[1]), json, TimeSpan.FromSeconds((int)context.Options["duration"]), true))
			{
				cache.SetValue(GetStorageTimestampKey(context.Arguments[0], context.Arguments[1]), timestamp, TimeSpan.FromSeconds((int)context.Options["duration"]));
			}
			else
			{
				timestamp = Zongsoft.Common.Convert.ConvertValue<DateTime>(cache.GetValue(GetStorageTimestampKey(context.Arguments[0], context.Arguments[1])));
			}

			if(_period <= 0 || (DateTime.Now - timestamp).TotalSeconds > _period)
			{
				var queue = queueProvder.GetQueue("SMS");
				queue.Enqueue(json);

				var duration = cache.GetDuration(GetStorageTimestampKey(context.Arguments[0], context.Arguments[1]));
				cache.SetValue(GetStorageTimestampKey(context.Arguments[0], context.Arguments[1]), DateTime.Now, duration.HasValue ? duration.Value : TimeSpan.FromSeconds((int)context.Options["duration"]));
			}
		}
		#endregion

		#region 私有方法
		private string GenerateCode(int length)
		{
			length = Math.Max(length, 4);
			var result = string.Empty;

			while(result.Length < length)
			{
				var text = ((uint)Zongsoft.Common.RandomGenerator.GenerateInt32()).ToString();
				result += text.Substring(0, Math.Min(text.Length, length - result.Length));
			}

			return result;
		}

		internal static string GetStorageKey(string source, string destination)
		{
			return string.Format("Zongsoft.Security.Authenticode:{0}:{1}", source.ToLowerInvariant().Trim(), destination.ToLowerInvariant().Trim());
		}

		internal static string GetStorageTimestampKey(string source, string destination)
		{
			return GetStorageKey(source, destination) + ":Timestamp";
		}
		#endregion
	}
}
