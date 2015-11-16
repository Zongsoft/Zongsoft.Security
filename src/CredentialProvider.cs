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
using System.Collections.Concurrent;
using System.Linq;

namespace Zongsoft.Security
{
	public class CredentialProvider : Zongsoft.Services.ServiceBase, ICredentialProvider
	{
		#region 私有常量
		private const string DefaultCacheName = "Zongsoft.Security.Membership.Credentials";
		#endregion

		#region 成员字段
		private TimeSpan _renewalPeriod;
		private Zongsoft.Runtime.Caching.MemoryCache _memoryCache;
		#endregion

		#region 构造函数
		public CredentialProvider(Zongsoft.Services.IServiceProvider serviceProvider) : base(serviceProvider)
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
		#endregion

		#region 公共方法
		public Credential Register(Membership.User user, string scene, IDictionary<string, object> extendedProperties = null)
		{
			//创建一个新的凭证对象
			var credential = this.CreateCredential(user, scene, extendedProperties);

			if(credential == null)
				throw new InvalidOperationException();

			//注册新建的凭证
			this.Register(credential);

			//返回注册成功的凭证
			return credential;
		}

		public virtual void Unregister(string credentialId)
		{
			if(string.IsNullOrWhiteSpace(credentialId))
				return;

			var storage = this.EnsureService<Zongsoft.Runtime.Caching.ICache>();

			//获取指定编号的凭证对象
			var credential = this.GetCredential(credentialId);

			//从本地内存缓存中把指定编号的凭证对象删除
			_memoryCache.Remove(credentialId);

			if(credential != null)
			{
				//将凭证资料从缓存容器中删除
				storage.Remove(this.GetCacheKeyOfCredential(credentialId));
				//将当前用户及场景对应的凭证号记录删除
				storage.Remove(this.GetCacheKeyOfUser(credential.User.UserId, credential.Scene));

				//获取当前命名空间包含的所有凭证集合
				var namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(credential.Namespace)) as ICollection<string>;

				//将当前凭证号从命名空间集合中删除
				if(namespaces != null)
					namespaces.Remove(credentialId);
			}
		}

		public Credential Renew(string credentialId)
		{
			if(string.IsNullOrWhiteSpace(credentialId))
				throw new ArgumentNullException("credentialId");

			var storage = this.EnsureService<Zongsoft.Runtime.Caching.ICache>();

			//查找指定编号的凭证对象
			var credential = this.GetCredential(credentialId);

			//指定编号的凭证不存在，则中止续约
			if(credential == null)
				return null;

			//创建一个新的凭证对象
			credential = this.CreateCredential(credential.User, credential.Scene, (credential.HasExtendedProperties ? credential.ExtendedProperties : null));

			//将新的凭证对象以JSON文本的方式保存到物理存储层中
			storage.SetValue(this.GetCacheKeyOfCredential(credential.CredentialId), this.SerializeCertificationToJson(credential), credential.Duration);

			//将当前用户及场景对应的凭证号更改为新创建的凭证号
			storage.SetValue(this.GetCacheKeyOfUser(credential.User.UserId, credential.Scene), credential.CredentialId, credential.Duration);

			//将原来的凭证从物理存储层中删除
			storage.Remove(credentialId);

			//获取当前凭证所在的命名空间集
			var namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(credential.Namespace)) as ICollection<string>;

			if(namespaces != null)
			{
				//将原来的凭证号从命名空间集中删除
				namespaces.Remove(credentialId);

				//将续约后的新凭证号加入到命名空间集中
				namespaces.Add(credential.CredentialId);
			}
			else
			{
				storage.SetValue(this.GetCacheKeyOfNamespace(credential.Namespace), new string[]{ credential.CredentialId });
			}

			//将原来的凭证从本地内存缓存中删除
			_memoryCache.Remove(credentialId);

			//将新建的凭证保存到本地内存缓存中
			_memoryCache.SetValue(credential.CredentialId, credential, DateTime.Now.AddSeconds(credential.Duration.TotalSeconds / 2));

			//返回续约后的新凭证对象
			return credential;
		}

		public int GetCount()
		{
			return this.GetCount(null);
		}

		public int GetCount(string @namespace)
		{
			var storage = this.EnsureService<Zongsoft.Runtime.Caching.ICache>();
			var namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(@namespace)) as ICollection;

			if(namespaces == null)
				return 0;

			return namespaces.Count;
		}

		public bool Validate(string credentialId)
		{
			if(string.IsNullOrWhiteSpace(credentialId))
				throw new ArgumentNullException("credentialId");

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

			var storage = this.EnsureService<Zongsoft.Runtime.Caching.ICache>();

			//在物理存储层中查找指定编号的凭证对象的缓存字典
			var dictionary = storage.GetValue(this.GetCacheKeyOfCredential(credentialId)) as IDictionary;

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

		public Credential GetCredential(int userId, string scene)
		{
			var storage = this.EnsureService<Zongsoft.Runtime.Caching.ICache>();
			var credentialId = storage.GetValue(this.GetCacheKeyOfUser(userId, scene)) as string;

			if(string.IsNullOrWhiteSpace(credentialId))
				return null;

			return this.GetCredential(credentialId);
		}

		public IEnumerable<Credential> GetCredentials(string @namespace)
		{
			var storage = this.EnsureService<Zongsoft.Runtime.Caching.ICache>();
			var namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(@namespace)) as IDictionary;

			if(namespaces == null)
				yield break;

			foreach(DictionaryEntry entry in namespaces)
			{
				yield return this.GetCredential(entry.Key.ToString());
			}
		}
		#endregion

		#region 虚拟方法
		protected virtual string GenerateCredentialId()
		{
			return Zongsoft.Common.RandomGenerator.GenerateString(16);
		}

		protected virtual Credential CreateCredential(Membership.User user, string scene, IDictionary<string, object> extendedProperties)
		{
			return new Credential(this.GenerateCredentialId(), user, scene, _renewalPeriod, DateTime.Now, extendedProperties);
		}

		protected virtual void Register(Credential credential)
		{
			var storage = this.EnsureService<Zongsoft.Runtime.Caching.ICache>();

			//声明命名空间对应的所有凭证的集合
			ICollection<string> namespaces = null;

			//获取要注册的用户及应用场景已经注册的凭证号
			var originalCredentialId = storage.GetValue(this.GetCacheKeyOfUser(credential.User.UserId, credential.Scene)) as string;

			//确保同个用户在相同场景下只能存在一个凭证：如果获取的凭证号不为空并且有值，则
			if(originalCredentialId != null && originalCredentialId.Length > 0)
			{
				//将同名用户及场景下的原来的凭证删除（即踢下线）
				storage.Remove(this.GetCacheKeyOfCredential(originalCredentialId));

				//获取命名空间的凭证集合
				namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(credential.Namespace)) as ICollection<string>;

				//将原来的凭证号从对应的命名空间集合中删除
				if(namespaces != null)
					namespaces.Remove(originalCredentialId);

				//将本地内存缓存中的凭证对象删除
				_memoryCache.Remove(originalCredentialId);

			}

			//设置当前用户及场景所对应的唯一凭证号为新注册的凭证号
			storage.SetValue(this.GetCacheKeyOfUser(credential.User.UserId, credential.Scene), credential.CredentialId, credential.Duration);

			//将当前凭证信息以JSON文本的方式保存到物理存储层中
			storage.SetValue(this.GetCacheKeyOfCredential(credential.CredentialId), this.SerializeCertificationToJson(credential), credential.Duration);

			if(namespaces == null)
			{
				//获取当前凭证所在的命名空间的集合
				namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(credential.Namespace)) as ICollection<string>;

				//如果命名空间集合为空则创建它，并初始化包含当前凭证号，否则直接在集合中添加当前凭证号
				if(namespaces == null)
					storage.SetValue(this.GetCacheKeyOfNamespace(credential.Namespace), new string[] { credential.CredentialId });
				else
					namespaces.Add(credential.CredentialId);
			}
			else
			{
				namespaces.Add(credential.CredentialId);
			}

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

		#region 私有方法
		private Credential EnsureCredentialsTimeout(string credentialId, DateTime timestamp)
		{
			if(string.IsNullOrWhiteSpace(credentialId))
				throw new ArgumentNullException("credentialId");

			var storage = this.EnsureService<Zongsoft.Runtime.Caching.ICache>();

			//在缓存容器中查找指定编号的凭证对象的序列化后的JSON文本
			var text = storage.GetValue(this.GetCacheKeyOfCredential(credentialId)) as string;

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
			storage.SetValue(this.GetCacheKeyOfCredential(credentialId), this.SerializeCertificationToJson(credential), duration);

			//顺延当前用户及场景对应凭证号的缓存项
			storage.SetDuration(this.GetCacheKeyOfUser(credential.UserId, credential.Scene), duration);

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

		private string GetCacheKeyOfUser(int userId, string scene)
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

		private string GetCacheKeyOfNamespace(string @namespace)
		{
			if(string.IsNullOrWhiteSpace(@namespace))
				return "Zongsoft.Security.Credential.Namespace";

			return "Zongsoft.Security.Credential.Namespace:" + @namespace.Trim().ToLowerInvariant();
		}
		#endregion
	}
}
