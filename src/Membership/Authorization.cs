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
	public class Authorization : IAuthorization
	{
		#region 成员字段
		private IDataAccess _dataAccess;
		private IMemberProvider _memberProvider;
		#endregion

		#region 事件定义
		public event EventHandler<AuthorizationEventArgs> Authorizing;
		public event EventHandler<AuthorizationEventArgs> Authorized;
		#endregion

		#region 构造函数
		public Authorization()
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

		[ServiceDependency]
		public IMemberProvider MemberProvider
		{
			get
			{
				return _memberProvider;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_memberProvider = value;
			}
		}
		#endregion

		#region 公共方法
		public bool Authorize(uint userId, string schemaId, string actionId)
		{
			if(string.IsNullOrWhiteSpace(schemaId))
				throw new ArgumentNullException("schemaId");

			//创建授权事件参数
			var args = new AuthorizationEventArgs(userId, schemaId, actionId, true);

			//激发“Authorizing”事件
			this.OnAuthorizing(args);

			//如果时间参数指定的验证结果为失败，则直接返回失败
			if(!args.IsAuthorized)
				return false;

			//如果指定的用户属于系统内置的管理员角色则立即返回授权通过
			if(this.MemberProvider.InRoles(userId, Role.Administrators))
				return true;

			//获取指定的安全凭证对应的有效的授权状态集
			var states = this.Authorizes(userId, MemberType.User);

			if(string.IsNullOrWhiteSpace(actionId) || actionId == "*")
				args.IsAuthorized = states != null && states.Any(state => string.Equals(state.SchemaId, schemaId, StringComparison.OrdinalIgnoreCase));
			else
				args.IsAuthorized = states != null && states.Any(state => string.Equals(state.SchemaId, schemaId, StringComparison.OrdinalIgnoreCase) &&
				                                                          string.Equals(state.ActionId, actionId, StringComparison.OrdinalIgnoreCase));

			//激发“Authorized”事件
			this.OnAuthorized(args);

			//返回最终的验证结果
			return args.IsAuthorized;
		}

		public IEnumerable<AuthorizationState> Authorizes(uint memberId, MemberType memberType)
		{
			return this.GetAuthorizedStates(memberId, memberType);

			//将结果缓存在内存容器中，默认有效期为10分钟
			return Zongsoft.Runtime.Caching.MemoryCache.Default.GetValue("Zongsoft.Security.Authorization:" + memberType.ToString() + ":" + memberId.ToString(),
				key => new Zongsoft.Runtime.Caching.CacheEntry(this.GetAuthorizedStates(memberId, memberType), TimeSpan.FromMinutes(10))) as IEnumerable<AuthorizationState>;
		}
		#endregion

		#region 虚拟方法
		protected virtual ICollection<AuthorizationState> GetAuthorizedStates(uint memberId, MemberType memberType)
		{
			var conditions = Condition.Equal("MemberId", memberId) & Condition.Equal("MemberType", memberType);

			//获取指定成员的所有上级角色集和上级角色的层级列表
			if(MembershipHelper.GetAncestors(this.DataAccess, memberId, memberType, out var flats, out var hierarchies) > 0)
			{
				//如果指定成员有上级角色，则进行权限定义的查询条件还需要加上所有上级角色
				conditions = ConditionCollection.Or(
					conditions,
					Condition.In("MemberId", flats.Select(p => p.RoleId)) & Condition.Equal("MemberType", MemberType.Role)
				);
			}

			//获取指定条件的所有权限定义（注：禁止分页查询，并即时加载到数组中）
			var permissions = this.DataAccess.Select<PermissionEntity>(MembershipHelper.DATA_ENTITY_PERMISSION, conditions, Paging.Disable).ToArray();

			//获取指定条件的所有权限过滤定义（注：禁止分页查询，并即时加载到数组中）
			var permissionFilters = this.DataAccess.Select<PermissionFilterEntity>(MembershipHelper.DATA_ENTITY_PERMISSION_FILTER, conditions, Paging.Disable).ToArray();

			var states = new HashSet<AuthorizationState>();
			IEnumerable<PermissionEntity> prepares;
			IEnumerable<AuthorizationState> grants, denies;

			//如果上级角色层级列表不为空则进行分层过滤
			if(hierarchies != null && hierarchies.Count > 0)
			{
				//从最顶层（即距离指定成员最远的层）开始到最底层（集距离指定成员最近的层）
				for(int i = hierarchies.Count - 1; i >= 0; i--)
				{
					//定义权限集过滤条件：当前层级的角色集的所有权限定义
					prepares = permissions.Where(p => hierarchies[i].Any(role => role.RoleId == p.MemberId) && p.MemberType == MemberType.Role);

					grants = prepares.Where(p => p.Granted).Select(p => new AuthorizationState(p.SchemaId, p.ActionId)).ToArray();
					denies = prepares.Where(p => !p.Granted).Select(p => new AuthorizationState(p.SchemaId, p.ActionId)).ToArray();

					states.UnionWith(grants);  //合并授予的权限定义
					states.ExceptWith(denies); //排除拒绝的权限定义

					//更新授权集中的相关目标的过滤文本
					this.SetPermissionFilters(states, permissionFilters.Where(p => hierarchies[i].Any(role => role.RoleId == p.MemberId) && p.MemberType == MemberType.Role));
				}
			}

			//查找权限定义中当前成员的设置项
			prepares = permissions.Where(p => p.MemberId == memberId && p.MemberType == memberType);

			grants = prepares.Where(p => p.Granted).Select(p => new AuthorizationState(p.SchemaId, p.ActionId)).ToArray();
			denies = prepares.Where(p => !p.Granted).Select(p => new AuthorizationState(p.SchemaId, p.ActionId)).ToArray();

			states.UnionWith(grants);  //合并授予的权限定义
			states.ExceptWith(denies); //排除拒绝的权限定义

			//更新授权集中的相关目标的过滤文本
			this.SetPermissionFilters(states, permissionFilters.Where(p => p.MemberId == memberId && p.MemberType == memberType));

			return states;
		}
		#endregion

		#region 事件激发
		protected virtual void OnAuthorizing(AuthorizationEventArgs args)
		{
			var handler = this.Authorizing;

			if(handler != null)
				handler(this, args);
		}

		protected virtual void OnAuthorized(AuthorizationEventArgs args)
		{
			var handler = this.Authorized;

			if(handler != null)
				handler(this, args);
		}
		#endregion

		#region 私有方法
		private void SetPermissionFilters(IEnumerable<AuthorizationState> states, IEnumerable<PermissionFilterEntity> filters)
		{
			var groups = filters.GroupBy(p => new AuthorizationState(p.SchemaId, p.ActionId));

			foreach(var group in groups)
			{
				var state = states.FirstOrDefault(p => p.Equals(group.Key));

				if(state != null)
				{
					if(string.IsNullOrWhiteSpace(state.Filter))
						state.Filter = string.Join("; ", group.Select(p => p.Filter));
					else
						state.Filter += " | " + string.Join("; ", group.Select(p => p.Filter));
				}
			}
		}
		#endregion

		#region 嵌套结构
		private struct PermissionEntity
		{
			public uint MemberId
			{
				get;
				set;
			}

			public MemberType MemberType
			{
				get;
				set;
			}

			public string SchemaId
			{
				get;
				set;
			}

			public string ActionId
			{
				get;
				set;
			}

			public bool Granted
			{
				get;
				set;
			}
		}

		private struct PermissionFilterEntity
		{
			public uint MemberId
			{
				get;
				set;
			}

			public MemberType MemberType
			{
				get;
				set;
			}

			public string SchemaId
			{
				get;
				set;
			}

			public string ActionId
			{
				get;
				set;
			}

			public string Filter
			{
				get;
				set;
			}
		}
		#endregion
	}
}
