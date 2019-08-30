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
using System.Collections;
using System.Collections.Generic;

using Zongsoft.Common;
using Zongsoft.Runtime.Caching;

namespace Zongsoft.Security.Membership
{
	/// <summary>
	/// 表示用户验证失败的处理器。
	/// </summary>
	public class Attempter
	{
		#region 成员字段
		private ICache _cache;
		#endregion

		#region 公共属性
		public ICache Cache
		{
			get => _cache;
			set => _cache = value ?? throw new ArgumentNullException();
		}

		public Options.IAttempterOption Option
		{
			get; set;
		}
		#endregion

		#region 公共方法
		/// <summary>
		/// 校验指定用户是否可以继续验证。
		/// </summary>
		/// <param name="identity">指定待验证的用户标识。</param>
		/// <param name="scene">表示验证操作的场景。</param>
		/// <returns>如果校验成功则返回真(True)，否则返回假(False)。</returns>
		public bool Verify(string identity, string @namespace)
		{
			var option = this.Option;

			if(option == null || option.Threshold < 1)
				return true;

			var cache = this.Cache;

			if(cache == null)
				return true;

			return cache.GetValue<int>(GetCacheKey(identity, @namespace)) < option.Threshold;
		}

		/// <summary>
		/// 验证成功方法。
		/// </summary>
		/// <param name="identity">指定验证成功的用户标识。</param>
		/// <param name="scene">表示验证操作的场景。</param>
		public void Done(string identity, string @namespace)
		{
			var cache = this.Cache;

			if(cache != null)
				cache.Remove(GetCacheKey(identity, @namespace));
		}

		/// <summary>
		/// 验证失败方法。
		/// </summary>
		/// <param name="identity">指定验证失败的用户标识。</param>
		/// <param name="scene">表示验证操作的场景。</param>
		/// <returns>返回验证失败是否超过阈值，如果返回真(True)则表示失败次数超过阈值。</returns>
		public bool Fail(string identity, string @namespace)
		{
			var sequence = this.Cache as ISequence;

			if(sequence == null)
				throw new InvalidOperationException($"The cache of authentication failover does not support the increment(ISequence) operation.");

			//获取验证失败的阈值和锁定时长
			this.GetAttempts(out var threshold, out var window);

			if(threshold < 1 || window == TimeSpan.Zero)
				return false;

			var KEY = GetCacheKey(identity, @namespace);
			var attempts = sequence.Increment(KEY);

			//如果失败计数器为新增（即递增结果为零或1），或者失败计数器到达限制数；
			//则更新失败计数器的过期时长为指定的锁定时长。
			if(attempts == 0 || attempts == 1 || attempts == threshold)
				this.Cache.SetExpiry(KEY, window);

			return attempts >= threshold;
		}
		#endregion

		#region 私有方法
		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private void GetAttempts(out int threshold, out TimeSpan window)
		{
			threshold = 3;
			window = TimeSpan.FromHours(1);

			var option = this.Option;

			if(option != null)
			{
				threshold = option.Threshold;
				window = option.Window;
			}
		}

		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private static string GetCacheKey(string identity, string @namespace)
		{
			const string KEY_PREFIX = "Zongsoft.Security.Attempts";

			return string.IsNullOrEmpty(@namespace) ?
				$"{KEY_PREFIX}:{identity.ToLowerInvariant().Trim()}" :
				$"{KEY_PREFIX}:{identity.ToLowerInvariant().Trim()}!{@namespace.ToLowerInvariant().Trim()}";
		}
		#endregion
	}
}
