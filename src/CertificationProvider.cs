﻿/*
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
	public class CertificationProvider : ICertificationProvider
	{
		#region 私有常量
		private const string DefaultCacheName = "Zongsoft.Security.Membership.Certification";
		#endregion

		#region 成员字段
		private TimeSpan _renewalPeriod;
		private Zongsoft.Runtime.Caching.ICache _storage;
		private Zongsoft.Runtime.Caching.MemoryCache _memoryCache;
		#endregion

		#region 构造函数
		public CertificationProvider()
		{
			_renewalPeriod = TimeSpan.FromHours(2);
			_memoryCache = new Runtime.Caching.MemoryCache("Zongsoft.CertificationProvider.MemoryCache");

			//挂载内存缓存容器的事件
			_memoryCache.Changed += MemoryCache_Changed;
		}

		public CertificationProvider(Zongsoft.Runtime.Caching.ICache storage)
		{
			if(storage == null)
				throw new ArgumentNullException("storage");

			_storage = storage;
			_renewalPeriod = TimeSpan.FromHours(2);
			_memoryCache = new Runtime.Caching.MemoryCache("Zongsoft.CertificationProvider.MemoryCache");

			//挂载内存缓存容器的事件
			_memoryCache.Changed += MemoryCache_Changed;
		}
		#endregion

		#region 公共属性
		/// <summary>
		/// 获取或设置凭证提供程序的数据存储容器。
		/// </summary>
		public Zongsoft.Runtime.Caching.ICache Storage
		{
			get
			{
				return _storage;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_storage = value;
			}
		}

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
		public Certification Register(Membership.User user, string scene, IDictionary<string, object> extendedProperties = null)
		{
			//创建一个新的凭证对象
			var certification = this.CreateCertification(user, scene, extendedProperties);

			if(certification == null)
				throw new InvalidOperationException();

			//注册新建的凭证
			this.Register(certification);

			//返回注册成功的凭证
			return certification;
		}

		public virtual void Unregister(string certificationId)
		{
			if(string.IsNullOrWhiteSpace(certificationId))
				return;

			var storage = this.EnsureStorage();

			//获取指定编号的凭证对象
			var certification = this.GetCertification(certificationId);

			//从本地内存缓存中把指定编号的凭证对象删除
			_memoryCache.Remove(certificationId);

			if(certification != null)
			{
				//将凭证资料从缓存容器中删除
				storage.Remove(this.GetCacheKeyOfCertification(certificationId));
				//将当前用户及场景对应的凭证号记录删除
				storage.Remove(this.GetCacheKeyOfUser(certification.User.UserId, certification.Scene));

				//获取当前命名空间包含的所有凭证集合
				var namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(certification.Namespace), null) as ICollection<string>;

				//将当前凭证号从命名空间集合中删除
				if(namespaces != null)
					namespaces.Remove(certificationId);
			}
		}

		public Certification Renew(string certificationId)
		{
			if(string.IsNullOrWhiteSpace(certificationId))
				throw new ArgumentNullException("certificationId");

			var storage = this.EnsureStorage();

			//查找指定编号的凭证对象
			var certification = this.GetCertification(certificationId);

			//指定编号的凭证不存在，则中止续约
			if(certification == null)
				return null;

			//创建一个新的凭证对象
			certification = this.CreateCertification(certification.User, certification.Scene, (certification.HasExtendedProperties ? certification.ExtendedProperties : null));

			//将新的凭证对象以字典的方式保存到物理存储层中
			storage.SetValue(this.GetCacheKeyOfCertification(certification.CertificationId), certification.ToDictionary());

			//将当前用户及场景对应的凭证号更改为新创建的凭证号
			storage.SetValue(this.GetCacheKeyOfUser(certification.User.UserId, certification.Scene), certification.CertificationId);

			//将原来的凭证从物理存储层中删除
			storage.Remove(certificationId);

			//获取当前凭证所在的命名空间集
			var namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(certification.Namespace), null) as ICollection<string>;

			if(namespaces != null)
			{
				//将原来的凭证号从命名空间集中删除
				namespaces.Remove(certificationId);

				//将续约后的新凭证号加入到命名空间集中
				namespaces.Add(certification.CertificationId);
			}
			else
			{
				storage.SetValue(this.GetCacheKeyOfNamespace(certification.Namespace), new string[]{ certification.CertificationId });
			}

			//将原来的凭证从本地内存缓存中删除
			_memoryCache.Remove(certificationId);

			//将新建的凭证保存到本地内存缓存中
			_memoryCache.SetValue(certification.CertificationId, certification, TimeSpan.FromSeconds(certification.Duration.TotalSeconds / 2));

			//返回续约后的新凭证对象
			return certification;
		}

		public int GetCount()
		{
			return this.GetCount(null);
		}

		public int GetCount(string @namespace)
		{
			var storage = this.EnsureStorage();
			var namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(@namespace), null) as ICollection;

			if(namespaces == null)
				return 0;

			return namespaces.Count;
		}

		public void Validate(string certificationId)
		{
			if(string.IsNullOrWhiteSpace(certificationId))
				throw new ArgumentNullException("certificationId");

			//首先从本地内存缓存中获取指定编号的凭证对象
			var certification = _memoryCache.GetValue(certificationId) as Certification;

			if(certification != null)
				certification.Timestamp = DateTime.Now;
			else
				this.SpreadCertificationExpries(certificationId);
		}

		public string GetNamespace(string certificationId)
		{
			if(string.IsNullOrWhiteSpace(certificationId))
				throw new ArgumentNullException("certificationId");

			//首先从本地内存缓存中获取指定编号的凭证对象
			var certification = _memoryCache.GetValue(certificationId, null) as Certification;

			//如果本地缓存获取成功则直接从其获取Namespace属性值返回
			if(certification != null)
				return certification.Namespace;

			var storage = this.EnsureStorage();

			//在物理存储层中查找指定编号的凭证对象的缓存字典
			var dictionary = storage.GetValue(this.GetCacheKeyOfCertification(certificationId)) as IDictionary;

			if(dictionary == null || dictionary.Count < 1)
				return null;

			return dictionary["Namespace"] as string;
		}

		public Certification GetCertification(string certificationId)
		{
			if(string.IsNullOrWhiteSpace(certificationId))
				return null;

			//首先从本地内存缓存中获取指定编号的凭证对象
			var certification = _memoryCache.GetValue(certificationId, null) as Certification;

			//如果本地缓存获取成功则直接返回
			if(certification != null)
				return certification;

			var storage = this.EnsureStorage();

			//从物理存储层获取凭证对象的序列化后的字典对象
			var dictionary = storage.GetValue(this.GetCacheKeyOfCertification(certificationId)) as IDictionary;

			if(dictionary != null)
			{
				//将存储层返回的凭证对象序列化的字典反序列化
				certification = Certification.FromDictionary(dictionary);

				//将反序列化后的凭证对象保存到本地内存缓存中
				_memoryCache.SetValue(certificationId, certification, TimeSpan.FromSeconds(certification.Duration.TotalSeconds / 2));
			}

			return null;
		}

		public Certification GetCertification(int userId, string scene)
		{
			var storage = this.EnsureStorage();
			var certificationId = storage.GetValue(this.GetCacheKeyOfUser(userId, scene), null) as string;

			if(string.IsNullOrWhiteSpace(certificationId))
				return null;

			return this.GetCertification(certificationId);
		}

		public IEnumerable<Certification> GetCertifications(string @namespace)
		{
			var storage = this.EnsureStorage();
			var namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(@namespace), null) as IDictionary;

			if(namespaces == null)
				yield break;

			foreach(DictionaryEntry entry in namespaces)
			{
				yield return this.GetCertification(entry.Key.ToString());
			}
		}
		#endregion

		#region 虚拟方法
		protected virtual string GenerateCertificationId()
		{
			return Zongsoft.Common.RandomGenerator.GenerateString(16);
		}

		protected virtual Certification CreateCertification(Membership.User user, string scene, IDictionary<string, object> extendedProperties)
		{
			return new Certification(this.GenerateCertificationId(), user, scene, _renewalPeriod, DateTime.Now, extendedProperties);
		}

		protected virtual void Register(Certification certification)
		{
			var storage = this.EnsureStorage();

			//声明命名空间对应的所有凭证的集合
			ICollection<string> namespaces = null;

			//获取要注册的用户及应用场景已经注册的凭证号
			var originalCertificationId = storage.GetValue(this.GetCacheKeyOfUser(certification.User.UserId, certification.Scene), null) as string;

			//确保同个用户在相同场景下只能存在一个凭证：如果获取的凭证号不为空并且有值，则
			if(originalCertificationId != null && originalCertificationId.Length > 0)
			{
				//将同名用户及场景下的原来的凭证删除（即踢下线）
				storage.Remove(this.GetCacheKeyOfCertification(originalCertificationId));

				//获取命名空间的凭证集合
				namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(certification.Namespace), null) as ICollection<string>;

				//将原来的凭证号从对应的命名空间集合中删除
				if(namespaces != null)
					namespaces.Remove(originalCertificationId);
			}

			//设置当前用户及场景所对应的唯一凭证号为新注册的凭证号
			storage.SetValue(this.GetCacheKeyOfUser(certification.User.UserId, certification.Scene), certification.CertificationId, certification.Duration);

			//将当前凭证信息以字典的方式保存到物理存储层中
			storage.SetValue(this.GetCacheKeyOfCertification(certification.CertificationId), certification.ToDictionary(), certification.Duration);

			if(namespaces == null)
			{
				//获取当前凭证所在的命名空间的集合
				namespaces = storage.GetValue(this.GetCacheKeyOfNamespace(certification.Namespace), null) as ICollection<string>;
				//namespaces = cache.GetValue(this.GetCacheKeyForNamespace(certification.Namespace), key => new Tuple<object, TimeSpan>(new HashSet<string>(new string[] { certification.CertificationId }), certification.Duration)) as ICollection<string>;

				//如果命名空间集合为空则创建它，并初始化包含当前凭证号，否则直接在集合中添加当前凭证号
				if(namespaces == null)
					storage.SetValue(this.GetCacheKeyOfNamespace(certification.Namespace), new string[]{ certification.CertificationId });
				else
					namespaces.Add(certification.CertificationId);
			}
			else
			{
				namespaces.Add(certification.CertificationId);
			}

			//将缓存对象保存到本地内存缓存中
			_memoryCache.SetValue(certification.CertificationId, certification, TimeSpan.FromSeconds(certification.Duration.TotalSeconds / 2));
		}
		#endregion

		#region 事件处理
		private void MemoryCache_Changed(object sender, Runtime.Caching.CacheChangedEventArgs e)
		{
			if(e.Reason != Runtime.Caching.CacheChangedReason.Expired)
				return;

			var certification = e.OldValue as Certification;
			var now = DateTime.Now;

			if(certification != null && (now > certification.IssuedTime && now < certification.Expires))
				this.SpreadCertificationExpries(e.OldKey);
		}
		#endregion

		#region 私有方法
		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private Zongsoft.Runtime.Caching.ICache EnsureStorage()
		{
			var storage = this.Storage;

			if(storage == null)
				throw new MissingMemberException(this.GetType().FullName, "Storage");

			return storage;
		}

		private void SpreadCertificationExpries(string certificationId)
		{
			if(string.IsNullOrWhiteSpace(certificationId))
				throw new ArgumentNullException("certificationId");

			var storage = this.EnsureStorage();

			//在当前缓存容器中查找指定编号的凭证对象
			var dictionary = storage.GetValue(this.GetCacheKeyOfCertification(certificationId), null) as IDictionary;

			if(dictionary == null || dictionary.Count < 1)
				throw new CertificationException(certificationId, "The certification is not exists.");

			//获取当前凭证的最后访问时间、凭证的周期、应用场景、用户编号
			var timestamp = Zongsoft.Common.Convert.ConvertValue<DateTime>(dictionary["Timestamp"]);
			var duration = Zongsoft.Common.Convert.ConvertValue<TimeSpan>(dictionary["Duration"], TimeSpan.Zero);
			var scene = Zongsoft.Common.Convert.ConvertValue<string>(dictionary["Scene"]);
			var userId = Zongsoft.Common.Convert.ConvertValue<int>(dictionary["User.UserId"]);

			var now = DateTime.Now;

			//如果现在时间超出凭证指定的期限范围则抛出异常
			if(now < timestamp || now > timestamp + duration)
				throw new CertificationException(certificationId, "The certification was expired.");

			//更新最新的访问时间
			dictionary["Timestamp"] = now;

			//顺延凭证的缓存项
			storage.SetDuration(this.GetCacheKeyOfCertification(certificationId), duration);

			//顺延当前用户及场景对应凭证号的缓存项
			storage.SetDuration(this.GetCacheKeyOfUser(userId, scene), duration);
		}

		private string GetCacheKeyOfUser(int userId, string scene)
		{
			if(string.IsNullOrWhiteSpace(scene))
				return "Zongsoft.Security:" + userId.ToString();
			else
				return string.Format("Zongsoft.Security:{0}:{1}", userId.ToString(), scene.Trim().ToLowerInvariant());
		}

		private string GetCacheKeyOfCertification(string certificationId)
		{
			if(string.IsNullOrWhiteSpace(certificationId))
				throw new ArgumentNullException("certificationId");

			return "Zongsoft.Security.Certification:" + certificationId.Trim().ToLowerInvariant();
		}

		private string GetCacheKeyOfNamespace(string @namespace)
		{
			if(string.IsNullOrWhiteSpace(@namespace))
				return "Zongsoft.Security.Certification.Namespaces";

			return "Zongsoft.Security.Certification.Namespaces:" + @namespace.Trim().ToLowerInvariant();
		}
		#endregion
	}
}
