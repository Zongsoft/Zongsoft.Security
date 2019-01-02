/*
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@gmail.com>
 *
 * Copyright (C) 2010-2017 Zongsoft Corporation <http://www.zongsoft.com>
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
using System.Linq;

using Zongsoft.Data;
using Zongsoft.Common;
using Zongsoft.Services;

namespace Zongsoft.Security.Membership
{
	public class RoleProvider : IRoleProvider, IMemberProvider
	{
		#region 成员字段
		private IDataAccess _dataAccess;
		private ISequence _sequence;
		private ICensorship _censorship;
		private Services.IServiceProvider _services;
		#endregion

		#region 构造函数
		public RoleProvider(Services.IServiceProvider serviceProvider)
		{
			_services = serviceProvider;
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

		[ServiceDependency]
		public ISequence Sequence
		{
			get
			{
				return _sequence;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_sequence = value;
			}
		}

		[ServiceDependency]
		public ICensorship Censorship
		{
			get
			{
				return _censorship;
			}
			set
			{
				_censorship = value;
			}
		}
		#endregion

		#region 角色管理
		public bool Exists(uint roleId)
		{
			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("RoleId", roleId));
		}

		public bool Exists(string name, string @namespace)
		{
			if(string.IsNullOrWhiteSpace(name))
				return false;

			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("Name", name) & MembershipHelper.GetNamespaceCondition(@namespace));
		}

		public Role GetRole(uint roleId)
		{
			return this.DataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("RoleId", roleId)).FirstOrDefault();
		}

		public Role GetRole(string name, string @namespace)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new ArgumentNullException("name");

			return this.DataAccess.Select<Role>(
													MembershipHelper.DATA_ENTITY_ROLE,
													Condition.Equal("Name", name) & MembershipHelper.GetNamespaceCondition(@namespace)
												).FirstOrDefault();
		}

		public IEnumerable<Role> GetRoles(string @namespace, Paging paging = null)
		{
			if(@namespace == "*")
				return this.DataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE);
			else
				return this.DataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, MembershipHelper.GetNamespaceCondition(@namespace), paging);
		}

		public bool SetNamespace(uint roleId, string @namespace)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_ROLE,
				new
				{
					Namespace = string.IsNullOrWhiteSpace(@namespace) ? null : @namespace.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", roleId)) > 0;
		}

		public int SetNamespaces(string oldNamespace, string newNamespace)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_ROLE,
				new
				{
					Namespace = string.IsNullOrWhiteSpace(newNamespace) ? null : newNamespace.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("Namespace", oldNamespace));
		}

		public int DeleteRoles(params uint[] roleIds)
		{
			if(roleIds == null || roleIds.Length < 1)
				return 0;

			int result = 0;

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				result = this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_ROLE, Condition.In("RoleId", roleIds));

				if(result > 0)
				{
					this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_MEMBER, Condition.Equal("MemberType", MemberType.Role) & Condition.In("MemberId", roleIds));
					this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_PERMISSION, Condition.Equal("MemberType", MemberType.Role) & Condition.In("MemberId", roleIds));
					this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_PERMISSION_FILTER, Condition.Equal("MemberType", MemberType.Role) & Condition.In("MemberId", roleIds));
				}

				transaction.Commit();
			}

			return result;
		}

		public int CreateRoles(params Role[] roles)
		{
			if(roles == null || roles.Length < 1)
				return 0;

			return this.CreateRoles((IEnumerable<Role>)roles);
		}

		public int CreateRoles(IEnumerable<Role> roles)
		{
			if(roles == null)
				return 0;

			foreach(var role in roles)
			{
				if(role == null)
					continue;

				if(string.IsNullOrWhiteSpace(role.Name))
					throw new ArgumentException("The role name is empty.");

				//验证指定的名称是否合法
				this.OnVerifyName(role.Name);

				//确保角色名是审核通过的
				this.Censor(role.Name);

				//确认角色名是否存在
				if(this.Exists(role.Name, role.Namespace))
					throw new DataConflictException(Zongsoft.Resources.ResourceUtility.GetString("Text.RoleConflict"));
			}

			foreach(var role in roles)
			{
				//处理未指定有效编号的角色对象
				if(role != null && role.RoleId < 1)
					role.RoleId = (uint)this.Sequence.Increment(MembershipHelper.SEQUENCE_ROLEID, 1, MembershipHelper.MINIMUM_ID);
			}

			return this.DataAccess.InsertMany(MembershipHelper.DATA_ENTITY_ROLE, roles);
		}

		public int UpdateRoles(params Role[] roles)
		{
			if(roles == null || roles.Length < 1)
				return 0;

			return this.UpdateRoles((IEnumerable<Role>)roles);
		}

		public int UpdateRoles(IEnumerable<Role> roles, string scope = null)
		{
			if(roles == null)
				return 0;

			if(string.IsNullOrWhiteSpace(scope))
				scope = "!CreatorId, !CreatedTime";
			else
				scope += ", !CreatorId, !CreatedTime";

			foreach(var role in roles)
			{
				if(role == null)
					continue;

				//只有当要更新的范围包含“Name”角色名才需要验证该属性值
				if(MembershipHelper.InScope<User>(scope, "Name"))
				{
					if(string.IsNullOrWhiteSpace(role.Name))
						throw new ArgumentException("The role name is empty.");

					//验证指定的名称是否合法
					this.OnVerifyName(role.Name);

					//确保角色名是审核通过的
					this.Censor(role.Name);

					//确认角色名是否存在
					if(this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_ROLE,
											  Condition.NotEqual("RoleId", role.RoleId) &
											  Condition.Equal("Name", role.Name) &
											  MembershipHelper.GetNamespaceCondition(role.Namespace)))
						throw new DataConflictException(Zongsoft.Resources.ResourceUtility.GetString("Text.RoleConflict"));
				}

				//确认获取当前上下文的用户编号
				if(MembershipHelper.EnsureCurrentUserId(out var userId))
					role.ModifierId = userId;

				//设置角色信息的最后变更时间
				role.ModifiedTime = DateTime.Now;
			}

			return this.DataAccess.UpdateMany(MembershipHelper.DATA_ENTITY_ROLE, roles, scope);
		}
		#endregion

		#region 成员管理
		public bool InRole(uint userId, uint roleId)
		{
			//获取指定用户编号对应的用户
			var user = this.DataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, Condition.Equal("UserId", userId), "!, UserId, Name, Namespace").FirstOrDefault();

			//如果指定的用户编号对应的是系统内置管理员（即 Administrator）则进行特殊处理，即系统内置管理员账号只能默认属于内置的管理员角色，它不能隶属于其它角色
			if(user != null && string.Equals(user.Name, User.Administrator, StringComparison.OrdinalIgnoreCase))
			{
				//获取指定角色编号对应的角色名
				var role = this.DataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("RoleId", roleId), "!, RoleId, Name, Namespace").FirstOrDefault();

				//如果指定的角色编号对应的是系统内置管理员角色（即 Administrators）则返回真，否则一律返回假。
				return role != null &&
				       string.Equals(role.Name, Role.Administrators, StringComparison.OrdinalIgnoreCase) &&
				       string.Equals(role.Namespace, user.Namespace, StringComparison.OrdinalIgnoreCase);
			}

			//处理非系统内置管理员账号
			if(MembershipHelper.GetAncestors(this.DataAccess, userId, MemberType.User, out var flats, out var hierarchies) > 0)
				return flats.Any(role => role.RoleId == roleId);

			return false;
		}

		public bool InRoles(uint userId, params string[] roleNames)
		{
			if(roleNames == null || roleNames.Length < 1)
				return false;

			//获取指定用户编号对应的用户
			var user = this.DataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, Condition.Equal("UserId", userId), "!, UserId, Name, Namespace").FirstOrDefault();

			//如果指定的用户编号对应的是系统内置管理员（即 Administrator）则进行特殊处理，即系统内置管理员账号只能默认属于内置的管理员角色，它不能隶属于其它角色
			if(user != null && string.Equals(user.Name, User.Administrator, StringComparison.OrdinalIgnoreCase))
				return roleNames.Contains(Role.Administrators, StringComparer.OrdinalIgnoreCase);

			//处理非系统内置管理员账号
			if(MembershipHelper.GetAncestors(this.DataAccess, userId, MemberType.User, out var flats, out var hierarchies) > 0)
				return flats.Any(role => roleNames.Contains(role.Name));

			return false;
		}

		public IEnumerable<Role> GetRoles(uint memberId, MemberType memberType)
		{
			var members = this.DataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER,
														 Condition.Equal("MemberId", memberId) & Condition.Equal("MemberType", memberType),
														 "Role");

			return members.Select(m => m.Role);
		}

		public IEnumerable<IMember> GetMembers(uint roleId)
		{
			//查出指定角色的所有子级成员
			var members = this.DataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER, Condition.Equal("RoleId", roleId));

			//从数据库中查找当前子级成员中的角色成员
			var roles = this.DataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, Condition.In("RoleId", members.Where(m => m.MemberType == MemberType.Role).Select(m => m.MemberId)));

			foreach(var role in roles)
			{
				yield return role;
			}

			//从数据库中查找当前子级成员中的用户成员
			var users = this.DataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, Condition.In("UserId", members.Where(m => m.MemberType == MemberType.User).Select(m => m.MemberId)));

			foreach(var user in users)
			{
				yield return user;
			}
		}

		public int SetMembers(uint roleId, params IMember[] members)
		{
			return this.SetMembers(roleId, members, false);
		}

		public int SetMembers(uint roleId, IEnumerable<IMember> members, bool shouldResetting = false)
		{
			if(members == null)
				return 0;

			//如果指定角色编号不存在则退出
			if(!this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("RoleId", roleId)))
				return -1;

			int count = 0;

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				//清空指定角色的所有成员
				if(shouldResetting)
					this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_MEMBER, Condition.Equal("RoleId", roleId));

				//插入指定的角色成员集到数据库中
				this.DataAccess.InsertMany(MembershipHelper.DATA_ENTITY_MEMBER, members.Select(p => new Member(roleId, p.MemberId, p.MemberType)));

				//提交事务
				transaction.Commit();
			}

			return count;
		}

		public bool RemoveMember(uint roleId, uint memberId, MemberType memberType)
		{
			return this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_MEMBER,
				Condition.Equal("RoleId", roleId) &
				Condition.Equal("MemberId", memberId) &
				Condition.Equal("MemberType", memberType)) > 0;
		}

		public int RemoveMembers(uint roleId, params IMember[] members)
		{
			if(members == null || members.Length < 1)
				return 0;

			return this.RemoveMembers(roleId, (IEnumerable<IMember>)members);
		}

		public int RemoveMembers(uint roleId, IEnumerable<IMember> members)
		{
			if(members == null)
				return 0;

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				var count = 0;

				foreach(var member in members)
				{
					if(member == null)
						continue;

					count += this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_MEMBER,
						Condition.Equal("RoleId", roleId) &
						Condition.Equal("MemberId", member.MemberId) &
						Condition.Equal("MemberType", member.MemberType));
				}

				//提交事务
				transaction.Commit();

				return count;
			}
		}
		#endregion

		#region 虚拟方法
		protected virtual void OnVerifyName(string name)
		{
			var validator = _services?.Resolve<IValidator<string>>("role.name");

			if(validator != null)
				validator.Validate(name, message => throw new SecurityException("rolename.illegality", message));
		}
		#endregion

		#region 私有方法
		private void Censor(string name)
		{
			var censorship = this.Censorship;

			if(censorship != null && censorship.IsBlocked(name, Zongsoft.Security.Censorship.KEY_NAMES, Zongsoft.Security.Censorship.KEY_SENSITIVES))
				throw new CensorshipException(string.Format("Illegal '{0}' name of role.", name));
		}
		#endregion
	}
}
