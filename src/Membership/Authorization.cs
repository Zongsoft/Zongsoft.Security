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
		private IMemberProvider _memberProvider;
		private IPermissionProvider _permissionProvider;
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

		[ServiceDependency]
		public IPermissionProvider PermissionProvider
		{
			get
			{
				return _permissionProvider;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_permissionProvider = value;
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
			var states = this.GetAuthorizedStates(userId, MemberType.User);

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

		public IEnumerable<AuthorizationState> GetAuthorizedStates(uint memberId, MemberType memberType)
		{
			//return this.GetAuthorizedStatesCore(memberId, memberType);

			//将结果缓存在内存容器中，默认有效期为10分钟
			return Zongsoft.Runtime.Caching.MemoryCache.Default.GetValue("Zongsoft.Security.Authorization:" + memberType.ToString() + ":" + memberId.ToString(),
				key => new Zongsoft.Runtime.Caching.CacheEntry(this.GetAuthorizedStatesCore(memberId, memberType), TimeSpan.FromMinutes(10))) as IEnumerable<AuthorizationState>;
		}
		#endregion

		#region 虚拟方法
		protected virtual IEnumerable<AuthorizationState> GetAuthorizedStatesCore(uint memberId, MemberType memberType)
		{
			var stack = new Stack<IEnumerable<Role>>();

			//递归获取当前成员所属角色信息，并将其所属上级角色依次压入指定的栈中
			this.RecursiveRoles(null, stack, this.MemberProvider.GetRoles(memberId, memberType));

			//创建授权状态集
			var grantedStates = new HashSet<AuthorizationState>();
			var deniedStates = new HashSet<AuthorizationState>();
			var states = new HashSet<AuthorizationState>();

			while(stack.Count > 0)
			{
				//从栈中弹出某个层级的角色集合
				var roles = stack.Pop();

				foreach(var role in roles)
				{
					//获取指定角色的授权集合
					this.SlicePermission(role.RoleId, MemberType.Role, grantedStates, deniedStates);
				}

				//将最终的授权结果集与显式授予集进行合并
				states.UnionWith(grantedStates);
				//从最终的授权结果集中删除显式拒绝集
				states.ExceptWith(deniedStates);

				//必须将当前层级的显式授予集清空
				grantedStates.Clear();
				//必须将当前层级的显式拒绝集清空
				deniedStates.Clear();
			}

			//获取指定成员的授权集合
			this.SlicePermission(memberId, memberType, grantedStates, deniedStates);

			//将最终的授权结果集与显式授予集进行合并
			states.UnionWith(grantedStates);
			//从最终的授权结果集中删除显式拒绝集
			states.ExceptWith(deniedStates);

			//将显式授予集清空
			grantedStates.Clear();
			//将显式拒绝集清空
			deniedStates.Clear();

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
		private void SlicePermission(uint memberId, MemberType memberType, HashSet<AuthorizationState> grantedStates, HashSet<AuthorizationState> deniedStates)
		{
			var permissions = this.PermissionProvider.GetPermissions(memberId, memberType);

			foreach(var permission in permissions)
			{
				if(permission.Granted)
					grantedStates.Add(new AuthorizationState(permission.SchemaId, permission.ActionId));
				else
					deniedStates.Add(new AuthorizationState(permission.SchemaId, permission.ActionId));
			}
		}

		private void RecursiveRoles(HashSet<string> hashSet, Stack<IEnumerable<Role>> stack, IEnumerable<Role> roles)
		{
			if(roles == null)
				return;

			var availableRoles = new List<Role>();

			if(hashSet == null)
				hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

			//对传入的角色集进行是否有循环引用的检测和过滤
			foreach(var role in roles)
			{
				string key = (role.Namespace + ":" + role.Name).ToLowerInvariant();

				//如果当前角色没有循环引用
				if(hashSet.Add(key))
					availableRoles.Add(role);
			}

			//将过滤过的没有循环引用的角色集加入到当前栈中
			stack.Push(availableRoles);

			//创建父级角色列表
			var parents = new List<Role>();

			foreach(var role in availableRoles)
			{
				//获取指定角色所属的的父级角色集
				roles = this.MemberProvider.GetRoles(role.RoleId, MemberType.Role);

				if(roles != null)
					parents.AddRange(roles);
			}

			//如果当前角色集的所有父级角色集不为空则递归调用
			if(parents != null && parents.Count > 0)
				this.RecursiveRoles(hashSet, stack, parents);
		}
		#endregion
	}
}
