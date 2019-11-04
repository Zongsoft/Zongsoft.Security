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
	public class Authorizer : IAuthorizer
	{
		#region 成员字段
		private IDataAccess _dataAccess;
		#endregion

		#region 事件定义
		public event EventHandler<AuthorizationContext> Authorizing;
		public event EventHandler<AuthorizationContext> Authorized;
		#endregion

		#region 构造函数
		public Authorizer()
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
		public bool Authorize(uint userId, string schema, string action)
		{
			return this.Authorize(this.DataAccess.Select<IUser>(Condition.Equal(nameof(IUser.UserId), userId)).FirstOrDefault(), schema, action);
		}

		public bool Authorize(IUserIdentity user, string schema, string action)
		{
			if(user == null)
				throw new ArgumentNullException(nameof(user));

			if(string.IsNullOrEmpty(schema))
				throw new ArgumentNullException(nameof(schema));

			//创建授权上下文对象
			var context = new AuthorizationContext(user, schema, action, true);

			//激发“Authorizing”事件
			this.OnAuthorizing(context);

			//如果时间参数指定的验证结果为失败，则直接返回失败
			if(!context.IsAuthorized)
				return false;

			//如果指定的用户属于系统内置的管理员角色则立即返回授权通过
			if(this.InRoles(user, MembershipHelper.Administrators))
				return true;

			//获取指定的安全凭证对应的有效的授权状态集
			var tokens = this.Authorizes(user);

			if(string.IsNullOrWhiteSpace(action) || action == "*")
				context.IsAuthorized = tokens != null && tokens.Any(state => string.Equals(state.Schema, schema, StringComparison.OrdinalIgnoreCase));
			else
				context.IsAuthorized = tokens != null && tokens.Any(
					token => string.Equals(token.Schema, schema, StringComparison.OrdinalIgnoreCase) &&
					         token.Actions.Any(p => string.Equals(p.Action, action, StringComparison.OrdinalIgnoreCase))
				);

			//激发“Authorized”事件
			this.OnAuthorized(context);

			//返回最终的验证结果
			return context.IsAuthorized;
		}

		public IEnumerable<AuthorizationToken> Authorizes(IUserIdentity user)
		{
			if(user == null)
				throw new ArgumentNullException(nameof(user));

			return this.GetAuthorizedTokens(user.Namespace, user.UserId, MemberType.User);
		}

		public IEnumerable<AuthorizationToken> Authorizes(IRole role)
		{
			if(role == null)
				throw new ArgumentNullException(nameof(role));

			return this.GetAuthorizedTokens(role.Namespace, role.RoleId, MemberType.Role);
		}

		public IEnumerable<AuthorizationToken> Authorizes(uint memberId, MemberType memberType)
		{
			string @namespace = null;

			if(memberType == MemberType.User)
			{
				//获取指定编号的用户对象
				var user = this.DataAccess.Select<IUser>(Condition.Equal(nameof(IUser.UserId), memberId), "!, UserId, Name, Namespace").FirstOrDefault();

				//如果指定编号的用户不存在，则退出
				if(user == null)
					return Array.Empty<AuthorizationToken>();

				@namespace = user.Namespace;
			}
			else
			{
				//获取指定编号的角色对象
				var role = this.DataAccess.Select<IRole>(Condition.Equal(nameof(IRole.RoleId), memberId), "!, RoleId, Name, Namespace").FirstOrDefault();

				//如果指定编号的角色不存在或是一个内置角色（内置角色没有归属），则退出
				if(role == null)
					return Array.Empty<AuthorizationToken>();

				@namespace = role.Namespace;
			}

			return this.GetAuthorizedTokens(@namespace, memberId, memberType);

			//将结果缓存在内存容器中，默认有效期为10分钟
			return Zongsoft.Runtime.Caching.MemoryCache.Default.GetValue("Zongsoft.Security.Authorization:" + memberType.ToString() + ":" + memberId.ToString(),
				key => new Zongsoft.Runtime.Caching.CacheEntry(this.GetAuthorizedTokens(@namespace, memberId, memberType), TimeSpan.FromMinutes(10))) as IEnumerable<AuthorizationToken>;
		}

		public bool InRole(uint userId, uint roleId)
		{
			//获取指定用户编号对应的用户
			var user = this.DataAccess.Select<IUser>(Condition.Equal(nameof(IUser.UserId), userId), "UserId, Name, Namespace").FirstOrDefault();

			//如果指定的用户编号对应的是系统内置管理员（即 Administrator）则进行特殊处理，即系统内置管理员账号只能默认属于内置的管理员角色，它不能隶属于其它角色
			if(user != null && string.Equals(user.Name, MembershipHelper.Administrator, StringComparison.OrdinalIgnoreCase))
			{
				//获取指定角色编号对应的角色名
				var role = this.DataAccess.Select<IRole>(Condition.Equal(nameof(IRole.RoleId), roleId) & Condition.Equal(nameof(IRole.Namespace), user.Namespace), "RoleId, Name, Namespace").FirstOrDefault();

				//如果指定的角色编号对应的是系统内置管理员角色（即 Administrators）则返回真，否则一律返回假。
				return role != null &&
					   string.Equals(role.Name, MembershipHelper.Administrators, StringComparison.OrdinalIgnoreCase) &&
					   string.Equals(role.Namespace, user.Namespace, StringComparison.OrdinalIgnoreCase);
			}

			//处理非系统内置管理员账号
			if(MembershipHelper.GetAncestors(this.DataAccess, user, out var flats, out var hierarchies) > 0)
				return flats.Any(role => role.RoleId == roleId);

			return false;
		}

		public bool InRoles(uint userId, params string[] roleNames)
		{
			if(roleNames == null || roleNames.Length < 1)
				return false;

			return this.InRoles(this.DataAccess.Select<IUser>(Condition.Equal(nameof(IUser.UserId), userId), "UserId, Name, Namespace").FirstOrDefault(), roleNames);
		}

		public bool InRoles(IUserIdentity user, params string[] roleNames)
		{
			if(user == null || user.Name == null || roleNames == null || roleNames.Length < 1)
				return false;

			//如果指定的用户编号对应的是系统内置管理员（即 Administrator）则进行特殊处理，即系统内置管理员账号只能默认属于内置的管理员角色，它不能隶属于其它角色
			if(string.Equals(user.Name, MembershipHelper.Administrator, StringComparison.OrdinalIgnoreCase))
				return roleNames.Contains(MembershipHelper.Administrators, StringComparer.OrdinalIgnoreCase);

			//处理非系统内置管理员账号
			if(MembershipHelper.GetAncestors(this.DataAccess, user, out var flats, out var hierarchies) > 0)
			{
				//如果所属的角色中包括系统内置管理员，则该用户自然属于任何角色
				return flats.Any(role =>
					string.Equals(role.Name, MembershipHelper.Administrators, StringComparison.OrdinalIgnoreCase) ||
					roleNames.Contains(role.Name)
				);
			}

			return false;
		}
		#endregion

		#region 虚拟方法
		protected virtual IEnumerable<AuthorizationToken> GetAuthorizedTokens(string @namespace, uint memberId, MemberType memberType)
		{
			var conditions = Condition.Equal("MemberId", memberId) & Condition.Equal("MemberType", memberType);

			//获取指定成员的所有上级角色集和上级角色的层级列表
			if(MembershipHelper.GetAncestors(this.DataAccess, @namespace, memberId, memberType, out var flats, out var hierarchies) > 0)
			{
				//如果指定成员有上级角色，则进行权限定义的查询条件还需要加上所有上级角色
				conditions = ConditionCollection.Or(
					conditions,
					Condition.In("MemberId", flats.Select(p => p.RoleId)) & Condition.Equal("MemberType", MemberType.Role)
				);
			}

			//获取指定条件的所有权限定义（注：禁止分页查询，并即时加载到数组中）
			var permissions = this.DataAccess.Select<Permission>(conditions, Paging.Disable).ToArray();

			//获取指定条件的所有权限过滤定义（注：禁止分页查询，并即时加载到数组中）
			var permissionFilters = this.DataAccess.Select<PermissionFilter>(conditions, Paging.Disable).ToArray();

			var states = new HashSet<AuthorizationState>();
			IEnumerable<Permission> prepares;
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

			foreach(var group in states.GroupBy(p => p.SchemaId))
			{
				yield return new AuthorizationToken(group.Key, group.Select(p => new AuthorizationToken.ActionToken(p.ActionId, p.Filter)));
			}
		}
		#endregion

		#region 事件激发
		protected virtual void OnAuthorizing(AuthorizationContext context)
		{
			this.Authorizing?.Invoke(this, context);
		}

		protected virtual void OnAuthorized(AuthorizationContext context)
		{
			this.Authorized?.Invoke(this, context);
		}
		#endregion

		#region 私有方法
		private void SetPermissionFilters(IEnumerable<AuthorizationState> states, IEnumerable<PermissionFilter> filters)
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

		#region 嵌套子类
		private class AuthorizationState : IEquatable<AuthorizationState>
		{
			#region 公共字段
			public readonly string SchemaId;
			public readonly string ActionId;
			public string Filter;
			#endregion

			#region 构造函数
			public AuthorizationState(string schemaId, string actionId, string filter = null)
			{
				if(string.IsNullOrEmpty(schemaId))
					throw new ArgumentNullException(nameof(schemaId));
				if(string.IsNullOrEmpty(actionId))
					throw new ArgumentNullException(nameof(actionId));

				this.SchemaId = schemaId.ToUpperInvariant();
				this.ActionId = actionId.ToUpperInvariant();
				this.Filter = filter;
			}
			#endregion

			#region 重写方法
			public bool Equals(AuthorizationState other)
			{
				return string.Equals(this.SchemaId, other.SchemaId) &&
				       string.Equals(this.ActionId, other.ActionId);
			}

			public override bool Equals(object obj)
			{
				if(obj == null || obj.GetType() != typeof(AuthorizationState))
					return false;

				return this.Equals((AuthorizationState)obj);
			}

			public override int GetHashCode()
			{
				return this.SchemaId.GetHashCode() ^ this.ActionId.GetHashCode();
			}

			public override string ToString()
			{
				if(string.IsNullOrEmpty(this.Filter))
					return this.SchemaId + ":" + this.ActionId;
				else
					return this.SchemaId + ":" + this.ActionId + "(" + this.Filter + ")";
			}
			#endregion
		}
		#endregion
	}
}
