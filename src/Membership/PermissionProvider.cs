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
using System.Linq;
using System.Collections.Generic;

using Zongsoft.Data;
using Zongsoft.Services;

namespace Zongsoft.Security.Membership
{
	public class PermissionProvider : IPermissionProvider
	{
		#region 成员字段
		private IDataAccess _dataAccess;
		#endregion

		#region 构造函数
		public PermissionProvider()
		{
		}
		#endregion

		#region 公共属性
		[ServiceDependency]
		public IDataAccess DataAccess
		{
			get
			{
				return _dataAccess;
			}
			set
			{
				_dataAccess = value ?? throw new ArgumentNullException();
			}
		}
		#endregion

		#region 公共方法
		public IEnumerable<Permission> GetPermissions(uint memberId, MemberType memberType, string schemaId = null)
		{
			var conditions = Condition.Equal(nameof(Permission.MemberId), memberId) & Condition.Equal(nameof(Permission.MemberType), memberType);

			if(!string.IsNullOrWhiteSpace(schemaId))
				conditions.Add(Condition.Equal(nameof(Permission.SchemaId), schemaId));

			return this.DataAccess.Select<Permission>(conditions);
		}

		public int SetPermissions(uint memberId, MemberType memberType, IEnumerable<Permission> permissions, bool shouldResetting = false)
		{
			return this.SetPermissions(memberId, memberType, null, permissions, shouldResetting);
		}

		public int SetPermissions(uint memberId, MemberType memberType, string schemaId, IEnumerable<Permission> permissions, bool shouldResetting = false)
		{
			var conditions = Condition.Equal(nameof(Permission.MemberId), memberId) & Condition.Equal(nameof(Permission.MemberType), memberType);

			if(!string.IsNullOrWhiteSpace(schemaId))
				conditions.Add(Condition.Equal(nameof(Permission.SchemaId), schemaId));

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				int count = 0;

				//清空指定成员的所有权限设置
				if(shouldResetting || permissions == null)
					count = this.DataAccess.Delete<Permission>(conditions);

				//写入指定的权限设置集到数据库中
				if(permissions != null)
					count = this.DataAccess.UpsertMany(
						permissions.Select(p => new Permission(memberId, memberType, (string.IsNullOrEmpty(schemaId) ? p.SchemaId : schemaId), p.ActionId, p.Granted)));

				//提交事务
				transaction.Commit();

				return count;
			}
		}

		public int RemovePermissions(uint memberId, MemberType memberType, string schemaId = null, string actionId = null)
		{
			var criteria = Condition.Equal(nameof(Permission.MemberId), memberId) &
			               Condition.Equal(nameof(Permission.MemberType), memberType);

			if(schemaId != null && schemaId.Length > 0)
				criteria.Add(Condition.Equal(nameof(Permission.SchemaId), schemaId));

			if(actionId != null && actionId.Length > 0)
				criteria.Add(Condition.Equal(nameof(Permission.ActionId), actionId));

			return this.DataAccess.Delete<Permission>(criteria);
		}

		public IEnumerable<PermissionFilter> GetPermissionFilters(uint memberId, MemberType memberType, string schemaId = null)
		{
			var conditions = Condition.Equal(nameof(PermissionFilter.MemberId), memberId) & Condition.Equal(nameof(PermissionFilter.MemberType), memberType);

			if(!string.IsNullOrWhiteSpace(schemaId))
				conditions.Add(Condition.Equal(nameof(PermissionFilter.SchemaId), schemaId));

			return this.DataAccess.Select<PermissionFilter>(conditions);
		}

		public int SetPermissionFilters(uint memberId, MemberType memberType, IEnumerable<PermissionFilter> permissionFilters, bool shouldResetting = false)
		{
			return this.SetPermissionFilters(memberId, memberType, null, permissionFilters, shouldResetting);
		}

		public int SetPermissionFilters(uint memberId, MemberType memberType, string schemaId, IEnumerable<PermissionFilter> permissionFilters, bool shouldResetting = false)
		{
			var conditions = Condition.Equal(nameof(PermissionFilter.MemberId), memberId) & Condition.Equal(nameof(PermissionFilter.MemberType), memberType);

			if(!string.IsNullOrWhiteSpace(schemaId))
				conditions.Add(Condition.Equal(nameof(PermissionFilter.SchemaId), schemaId));

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				int count = 0;

				//清空指定成员的所有权限设置
				if(shouldResetting || permissionFilters == null)
					count = this.DataAccess.Delete<PermissionFilter>(conditions);

				//插入指定的权限设置集到数据库中
				if(permissionFilters != null)
					count = this.DataAccess.UpsertMany(
						permissionFilters.Select(p => new PermissionFilter(memberId, memberType, (string.IsNullOrEmpty(schemaId) ? p.SchemaId : schemaId), p.ActionId, p.Filter)));

				//提交事务
				transaction.Commit();

				return count;
			}
		}

		public int RemovePermissionFilters(uint memberId, MemberType memberType, string schemaId = null, string actionId = null)
		{
			var criteria = Condition.Equal(nameof(Permission.MemberId), memberId) &
			               Condition.Equal(nameof(Permission.MemberType), memberType);

			if(schemaId != null && schemaId.Length > 0)
				criteria.Add(Condition.Equal(nameof(Permission.SchemaId), schemaId));

			if(actionId != null && actionId.Length > 0)
				criteria.Add(Condition.Equal(nameof(Permission.ActionId), actionId));

			return this.DataAccess.Delete<PermissionFilter>(criteria);
		}
		#endregion
	}
}
