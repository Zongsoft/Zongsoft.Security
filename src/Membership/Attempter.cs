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
		private Options.IConfiguration _configuration;
		#endregion

		#region 公共属性
		public ICache Cache
		{
			get => _cache;
			set => _cache = value ?? throw new ArgumentNullException();
		}

		[Services.ServiceDependency]
		public Options.IConfiguration Configuration
		{
			get => _configuration;
			set => _configuration = value;
		}
		#endregion

		#region 公共方法
		/// <summary>
		/// 校验指定用户是否可以继续验证。
		/// </summary>
		/// <param name="userId">指定待验证的用户编号。</param>
		/// <param name="scene">表示验证操作的场景。</param>
		/// <returns></returns>
		public bool Verify(uint userId, string scene = null)
		{
			var config = this.Configuration;

			if(config == null || config.AttemptThreshold < 1)
				return true;

			var cache = this.Cache;

			if(cache == null)
				return true;

			return cache.GetValue<int>(GetCacheKey(userId, scene)) < config.AttemptThreshold;
		}

		/// <summary>
		/// 验证成功方法。
		/// </summary>
		/// <param name="userId">指定验证成功的用户编号。</param>
		/// <param name="scene">表示验证操作的场景。</param>
		public void Done(uint userId, string scene = null)
		{
			var cache = this.Cache;

			if(cache != null)
				cache.Remove(GetCacheKey(userId, scene));
		}

		/// <summary>
		/// 验证失败方法。
		/// </summary>
		/// <param name="userId">指定验证失败的用户编号。</param>
		/// <param name="scene">表示验证操作的场景。</param>
		/// <returns>返回验证失败是否超过阈值，如果返回真(True)则表示失败次数超过阈值。</returns>
		public bool Fail(uint userId, string scene = null)
		{
			var sequence = this.Cache as ISequence;

			if(sequence == null)
				throw new InvalidOperationException($"The cache of authentication failover does not support the increment(ISequence) operation.");

			//获取验证失败的阈值和锁定时长
			this.GetAttempts(out var threshold, out var window);

			if(threshold < 1 || window == TimeSpan.Zero)
				return false;

			var KEY = GetCacheKey(userId, scene);
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

			var config = this.Configuration;

			if(config != null)
			{
				threshold = config.AttemptThreshold;
				window = TimeSpan.FromMinutes(config.AttemptWindow > 0 ? config.AttemptWindow : 60);
			}
		}

		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private static string GetCacheKey(uint userId, string scene = null)
		{
			if(string.IsNullOrEmpty(scene))
				return $"zongsoft.security:{userId.ToString()}:failover";
			else
				return $"zongsoft.security:{scene}:{userId.ToString()}:failover";
		}
		#endregion
	}
}
