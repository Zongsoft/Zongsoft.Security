/*
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@gmail.com>
 *
 * Copyright (C) 2010-2015 Zongsoft Corporation <http://www.zongsoft.com>
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

namespace Zongsoft.Security
{
	public class CredentialProvider : ICredentialProvider
	{
		#region 事件定义
		public event EventHandler<CredentialRegisterEventArgs> Registered;
		public event EventHandler<CredentialRegisterEventArgs> Registering;
		public event EventHandler<CredentialUnregisterEventArgs> Unregistered;
		public event EventHandler<CredentialUnregisterEventArgs> Unregistering;
		#endregion

		#region 私有常量
		private static readonly DateTime EPOCH = new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);
		#endregion

		#region 成员字段
		private TimeSpan _renewalPeriod;
		private Runtime.Caching.ICache _cache;
		private Runtime.Caching.MemoryCache _memoryCache;
		#endregion

		#region 构造函数
		public CredentialProvider()
		{
			_renewalPeriod = TimeSpan.FromHours(2);
			_memoryCache = new Runtime.Caching.MemoryCache("Zongsoft.Security.CredentialProvider.MemoryCache");

			//挂载内存缓存容器的事件
			_memoryCache.Changed += MemoryCache_Changed;
		}
		#endregion

		#region 公共属性
		/// <summary>
		/// 获取或设置凭证的默认续约周期，不能小于60秒。
		/// </summary>
		public TimeSpan RenewalPeriod
		{
			get
			{
				return _renewalPeriod;
			}
			set
			{
				_renewalPeriod = value.TotalMinutes < 1 ? TimeSpan.FromMinutes(1) : value;
			}
		}

		/// <summary>
		/// 获取或设置凭证的缓存器。
		/// </summary>
		public Runtime.Caching.ICache Cache
		{
			get
			{
				return _cache;
			}
			set
			{
				_cache = value ?? throw new ArgumentNullException();
			}
		}
		#endregion

		#region 公共方法
		public Credential Register(Membership.IUserIdentity user, string scene, IDictionary<string, object> parameters = null)
		{
			//创建一个新的凭证对象
			var credential = this.CreateCredential(user, scene, parameters);

			if(credential == null)
				throw new InvalidOperationException();

			//激发注册开始事件
			this.OnRegistering(user, scene, parameters);

			//注册新建的凭证
			this.Register(credential);

			//激发注册完成事件
			this.OnRegistered(credential);

			//返回注册成功的凭证
			return credential;
		}

		public virtual void Unregister(string credentialId)
		{
			if(string.IsNullOrWhiteSpace(credentialId))
				return;

			//激发准备注销事件
			this.OnUnregistering(credentialId);

			//获取指定编号的凭证对象
			var credential = this.GetCredential(credentialId);

			//从本地内存缓存中把指定编号的凭证对象删除
			_memoryCache.Remove(credentialId);

			if(credential != null)
			{
				//将凭证资料从缓存容器中删除
				this.Cache.Remove(this.GetCacheKeyOfCredential(credentialId));
				//将当前用户及场景对应的凭证号记录删除
				this.Cache.Remove(this.GetCacheKeyOfUser(credential.User.UserId, credential.Scene));
			}

			//激发注销完成事件
			this.OnUnregistered(credential);
		}

		public Credential Renew(string credentialId)
		{
			if(string.IsNullOrWhiteSpace(credentialId))
				throw new ArgumentNullException("credentialId");

			//查找指定编号的凭证对象
			var credential = this.GetCredential(credentialId);

			//指定编号的凭证不存在，则中止续约
			if(credential == null)
				return null;

			//创建一个新的凭证对象
			credential = this.CreateCredential(credential.User, credential.Scene, (credential.HasParameters ? credential.Parameters : null));

			//将新的凭证对象以JSON文本的方式保存到物理存储层中
			this.Cache.SetValue(this.GetCacheKeyOfCredential(credential.CredentialId), this.SerializeCertificationToJson(credential), credential.Duration);

			//将当前用户及场景对应的凭证号更改为新创建的凭证号
			this.Cache.SetValue(this.GetCacheKeyOfUser(credential.User.UserId, credential.Scene), credential.CredentialId, credential.Duration);

			//将原来的凭证从物理存储层中删除
			this.Cache.Remove(credentialId);

			//将原来的凭证从本地内存缓存中删除
			_memoryCache.Remove(credentialId);

			//将新建的凭证保存到本地内存缓存中
			_memoryCache.SetValue(credential.CredentialId, credential, DateTime.Now.AddSeconds(credential.Duration.TotalSeconds / 2));

			//返回续约后的新凭证对象
			return credential;
		}

		public bool Validate(string credentialId)
		{
			if(string.IsNullOrEmpty(credentialId))
				throw new ArgumentNullException(nameof(credentialId));

			//首先从本地内存缓存中获取指定编号的凭证对象
			var credential = _memoryCache.GetValue(credentialId) as Credential;

			if(credential != null)
			{
				credential.Timestamp = DateTime.Now;
				return true;
			}

			return this.EnsureCredentialsTimeout(credentialId, DateTime.Now) != null;
		}

		public string GetNamespace(string credentialId)
		{
			if(string.IsNullOrWhiteSpace(credentialId))
				throw new ArgumentNullException("credentialId");

			//首先从本地内存缓存中获取指定编号的凭证对象
			var credential = _memoryCache.GetValue(credentialId) as Credential;

			//如果本地缓存获取成功则直接从其获取Namespace属性值返回
			if(credential != null)
				return credential.Namespace;

			//在物理存储层中查找指定编号的凭证对象的缓存字典
			var dictionary = this.Cache.GetValue(this.GetCacheKeyOfCredential(credentialId)) as IDictionary;

			if(dictionary == null || dictionary.Count < 1)
				return null;

			return dictionary["Namespace"] as string;
		}

		public Credential GetCredential(string credentialId)
		{
			if(string.IsNullOrWhiteSpace(credentialId))
				return null;

			//首先从本地内存缓存中获取指定编号的凭证对象
			var credential = _memoryCache.GetValue(credentialId) as Credential;

			//如果本地缓存获取成功则直接返回
			if(credential != null)
				return credential;

			//顺延存储层的凭证并返回其凭证对象
			return this.EnsureCredentialsTimeout(credentialId, DateTime.Now);
		}

		public Credential GetCredential(uint userId, string scene)
		{
			var credentialId = this.Cache.GetValue(this.GetCacheKeyOfUser(userId, scene)) as string;

			if(string.IsNullOrWhiteSpace(credentialId))
				return null;

			return this.GetCredential(credentialId);
		}
		#endregion

		#region 虚拟方法
		/// <summary>
		/// 生成一个随机的凭证号。
		/// </summary>
		/// <returns>返回生成的凭证号。</returns>
		/// <remarks>
		///		<para>对实现者的建议：凭证号要求以数字打头。</para>
		/// </remarks>
		protected virtual string GenerateCredentialId()
		{
			//计算以自定义纪元的总秒数的时序值
			var timing = (ulong)Math.Abs((DateTime.UtcNow - EPOCH).TotalSeconds);

			//注意：必须确保凭证号以数字打头
			return timing.ToString() + Zongsoft.Common.Randomizer.GenerateString(8);
		}

		protected virtual Credential CreateCredential(Membership.IUserIdentity user, string scene, IDictionary<string, object> parameters)
		{
			return new Credential(this.GenerateCredentialId(), user, scene, _renewalPeriod, DateTime.Now, parameters);
		}

		protected virtual void Register(Credential credential)
		{
			//获取要注册的用户及应用场景已经注册的凭证号
			var originalCredentialId = this.Cache.GetValue(this.GetCacheKeyOfUser(credential.User.UserId, credential.Scene)) as string;

			//确保同个用户在相同场景下只能存在一个凭证：如果获取的凭证号不为空并且有值，则
			if(originalCredentialId != null && originalCredentialId.Length > 0)
			{
				//将同名用户及场景下的原来的凭证删除（即踢下线）
				this.Cache.Remove(this.GetCacheKeyOfCredential(originalCredentialId));

				//将本地内存缓存中的凭证对象删除
				_memoryCache.Remove(originalCredentialId);

			}

			//设置当前用户及场景所对应的唯一凭证号为新注册的凭证号
			this.Cache.SetValue(this.GetCacheKeyOfUser(credential.User.UserId, credential.Scene), credential.CredentialId, credential.Duration);

			//将当前凭证信息以JSON文本的方式保存到物理存储层中
			this.Cache.SetValue(this.GetCacheKeyOfCredential(credential.CredentialId), this.SerializeCertificationToJson(credential), credential.Duration);

			//将缓存对象保存到本地内存缓存中
			_memoryCache.SetValue(credential.CredentialId, credential, DateTime.Now.AddSeconds(credential.Duration.TotalSeconds / 2));
		}
		#endregion

		#region 事件处理
		private void MemoryCache_Changed(object sender, Runtime.Caching.CacheChangedEventArgs e)
		{
			if(e.Reason != Runtime.Caching.CacheChangedReason.Expired)
				return;

			var credential = e.OldValue as Credential;
			var now = DateTime.Now;

			if(credential != null && (now > credential.IssuedTime && now < credential.Expires))
				this.EnsureCredentialsTimeout(e.OldKey, credential.Timestamp);
		}
		#endregion

		#region 激发事件
		protected virtual void OnRegistered(Credential credential)
		{
			this.Registered?.Invoke(this, new CredentialRegisterEventArgs(credential));
		}

		protected virtual void OnRegistering(Membership.IUserIdentity user, string scene, IDictionary<string, object> parameters = null)
		{
			this.Registering?.Invoke(this, new CredentialRegisterEventArgs(user, scene, parameters));
		}

		protected virtual void OnUnregistered(Credential credential)
		{
			this.Unregistered?.Invoke(this, new CredentialUnregisterEventArgs(credential));
		}

		protected virtual void OnUnregistering(string credentialId)
		{
			this.Unregistering?.Invoke(this, new CredentialUnregisterEventArgs(credentialId));
		}
		#endregion

		#region 私有方法
		private Credential EnsureCredentialsTimeout(string credentialId, DateTime timestamp)
		{
			if(string.IsNullOrWhiteSpace(credentialId))
				throw new ArgumentNullException("credentialId");

			//在缓存容器中查找指定编号的凭证对象的序列化后的JSON文本
			var text = this.Cache.GetValue(this.GetCacheKeyOfCredential(credentialId)) as string;

			//如果缓存容器中没有找到指定编号的凭证则说明指定的编号无效或者该编号对应的凭证已经过期
			if(string.IsNullOrEmpty(text))
				return null;

			//反序列化JSON文本到凭证对象
			var credential = Zongsoft.Runtime.Serialization.Serializer.Json.Deserialize<Credential>(text);

			//如果反序列化失败则始终抛出异常
			if(credential == null)
				throw new InvalidOperationException("*** INTERNAL ERROR *** The credential text is invalid.");

			//如果指定的活动时间超出凭证的期限范围则返回空
			if(timestamp < credential.IssuedTime || timestamp > credential.Expires)
				return null;

			//计算实际要顺延的期限
			var duration = credential.Duration - (DateTime.Now - timestamp);

			//更新最新的访问时间
			credential.Timestamp = timestamp;

			//将当前凭证信息以JSON文本的方式保存到物理存储层中
			this.Cache.SetValue(this.GetCacheKeyOfCredential(credentialId), this.SerializeCertificationToJson(credential), duration);

			//顺延当前用户及场景对应凭证号的缓存项
			this.Cache.SetExpiry(this.GetCacheKeyOfUser(credential.User.UserId, credential.Scene), duration);

			//将缓存对象保存到本地内存缓存中
			_memoryCache.SetValue(credential.CredentialId, credential, DateTime.Now.AddSeconds(duration.TotalSeconds / 2));

			return credential;
		}

		private string SerializeCertificationToJson(Credential credential)
		{
			return Zongsoft.Runtime.Serialization.Serializer.Json.Serialize(credential, new Runtime.Serialization.TextSerializationSettings()
			{
				Indented = false,
				Typed = true,
				SerializationBehavior = Runtime.Serialization.SerializationBehavior.IgnoreDefaultValue,
			});
		}

		private string GetCacheKeyOfUser(uint userId, string scene)
		{
			if(string.IsNullOrWhiteSpace(scene))
				return "Zongsoft.Security:" + userId.ToString();
			else
				return string.Format("Zongsoft.Security:{0}:{1}", scene.Trim().ToLowerInvariant(), userId.ToString());
		}

		private string GetCacheKeyOfCredential(string credentialId)
		{
			if(string.IsNullOrWhiteSpace(credentialId))
				throw new ArgumentNullException("credentialId");

			return "Zongsoft.Security.Credential:" + credentialId.Trim().ToUpperInvariant();
		}
		#endregion
	}
}
