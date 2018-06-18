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
		public IDataAccess DataAccess
		{
			get
			{
				return _dataAccess ?? ServiceProviderFactory.Instance.Default.ResolveRequired<IDataAccessProvider>().Default;
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
			var conditions = Condition.Equal("MemberId", memberId) & Condition.Equal("MemberType", memberType);

			if(!string.IsNullOrWhiteSpace(schemaId))
				conditions.Add(Condition.Equal("SchemaId", schemaId));

			return this.DataAccess.Select<Permission>(MembershipHelper.DATA_ENTITY_PERMISSION, conditions);
		}

		public void SetPermissions(uint memberId, MemberType memberType, IEnumerable<Permission> permissions)
		{
			this.SetPermissions(memberId, memberType, null, permissions);
		}

		public void SetPermissions(uint memberId, MemberType memberType, string schemaId, IEnumerable<Permission> permissions)
		{
			var conditions = Condition.Equal("MemberId", memberId) & Condition.Equal("MemberType", memberType);

			if(!string.IsNullOrWhiteSpace(schemaId))
				conditions.Add(Condition.Equal("SchemaId", schemaId));

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				//清空指定成员的所有权限设置
				this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_PERMISSION, conditions);

				//插入指定的权限设置集到数据库中
				if(permissions != null)
					this.DataAccess.InsertMany(MembershipHelper.DATA_ENTITY_PERMISSION, permissions.Select(p => new PermissionEntity(memberId, memberType, schemaId, p)));

				//提交事务
				transaction.Commit();
			}
		}

		public IEnumerable<PermissionFilter> GetPermissionFilters(uint memberId, MemberType memberType, string schemaId = null)
		{
			var conditions = Condition.Equal("MemberId", memberId) & Condition.Equal("MemberType", memberType);

			if(!string.IsNullOrWhiteSpace(schemaId))
				conditions.Add(Condition.Equal("SchemaId", schemaId));

			return this.DataAccess.Select<PermissionFilter>(MembershipHelper.DATA_ENTITY_PERMISSION_FILTER, conditions);
		}

		public void SetPermissionFilters(uint memberId, MemberType memberType, IEnumerable<PermissionFilter> permissionFilters)
		{
			this.SetPermissionFilters(memberId, memberType, null, permissionFilters);
		}

		public void SetPermissionFilters(uint memberId, MemberType memberType, string schemaId, IEnumerable<PermissionFilter> permissionFilters)
		{
			var conditions = Condition.Equal("MemberId", memberId) & Condition.Equal("MemberType", memberType);

			if(!string.IsNullOrWhiteSpace(schemaId))
				conditions.Add(Condition.Equal("SchemaId", schemaId));

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				//清空指定成员的所有权限设置
				this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_PERMISSION_FILTER, conditions);

				//插入指定的权限设置集到数据库中
				if(permissionFilters != null)
					this.DataAccess.InsertMany(MembershipHelper.DATA_ENTITY_PERMISSION_FILTER, permissionFilters.Select(p => new PermissionFilterEntity(memberId, memberType, schemaId, p)));

				//提交事务
				transaction.Commit();
			}
		}
		#endregion

		#region 嵌套子类
		private struct PermissionEntity
		{
			#region 构造函数
			public PermissionEntity(uint memberId, MemberType memberType, string schemaId, Permission permission)
			{
				this.MemberId = memberId;
				this.MemberType = memberType;
				this.SchemaId = string.IsNullOrWhiteSpace(schemaId) ? permission.SchemaId : schemaId;
				this.ActionId = permission.ActionId;
				this.Granted = permission.Granted;
			}
			#endregion

			#region 公共属性
			public uint MemberId
			{
				get; set;
			}

			public MemberType MemberType
			{
				get; set;
			}

			public string SchemaId
			{
				get; set;
			}

			public string ActionId
			{
				get; set;
			}

			public bool Granted
			{
				get; set;
			}
			#endregion
		}

		private struct PermissionFilterEntity
		{
			#region 构造函数
			public PermissionFilterEntity(uint memberId, MemberType memberType, string schemaId, PermissionFilter permissionFilter)
			{
				this.MemberId = memberId;
				this.MemberType = memberType;
				this.SchemaId = string.IsNullOrWhiteSpace(schemaId) ? permissionFilter.SchemaId : schemaId;
				this.ActionId = permissionFilter.ActionId;
				this.Filter = permissionFilter.Filter;
			}
			#endregion

			#region 公共属性
			public uint MemberId
			{
				get; set;
			}

			public MemberType MemberType
			{
				get; set;
			}

			public string SchemaId
			{
				get; set;
			}

			public string ActionId
			{
				get; set;
			}

			public string Filter
			{
				get; set;
			}
			#endregion
		}
		#endregion
	}
}
