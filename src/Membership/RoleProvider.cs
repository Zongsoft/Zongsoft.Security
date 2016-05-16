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
using System.Linq;

using Zongsoft.Data;
using Zongsoft.Common;
using Zongsoft.Services;

namespace Zongsoft.Security.Membership
{
	public class RoleProvider : MarshalByRefObject, IRoleProvider, IMemberProvider
	{
		#region 成员字段
		private IDataAccess _dataAccess;
		private ISequence _sequence;
		private ICensorship _censorship;
		#endregion

		#region 构造函数
		public RoleProvider()
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
				if(value == null)
					throw new ArgumentNullException();

				_dataAccess = value;
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
		public bool Exists(int roleId)
		{
			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("RoleId", roleId));
		}

		public bool Exists(string name, string @namespace)
		{
			if(string.IsNullOrWhiteSpace(name))
				return false;

			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("Name", name) & Condition.Equal("Namespace", MembershipHelper.TrimNamespace(@namespace)));
		}

		public Role GetRole(int roleId)
		{
			return this.DataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("RoleId", roleId)).FirstOrDefault();
		}

		public Role GetRole(string name, string @namespace)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new ArgumentNullException("name");

			return this.DataAccess.Select<Role>(
													MembershipHelper.DATA_ENTITY_ROLE,
													Condition.Equal("Name", name) & Condition.Equal("Namespace", MembershipHelper.TrimNamespace(@namespace))
												).FirstOrDefault();
		}

		public IEnumerable<Role> GetAllRoles(string @namespace, Paging paging = null)
		{
			if(string.IsNullOrWhiteSpace(@namespace))
				return this.DataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, null, paging);
			else
				return this.DataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("Namespace", MembershipHelper.TrimNamespace(@namespace)), paging);
		}

		public int DeleteRoles(params int[] roleIds)
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
					role.RoleId = (int)this.Sequence.GetSequenceNumber(MembershipHelper.SEQUENCE_ROLEID, 1, MembershipHelper.MINIMUM_ID);
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

			foreach(var role in roles)
			{
				if(role == null)
					continue;

				//只有当要更新的范围包含“Name”角色名才需要验证该属性值
				if(MembershipHelper.InScope<User>(scope, "Name"))
				{
					if(string.IsNullOrWhiteSpace(role.Name))
						throw new ArgumentException("The role name is empty.");

					//确保角色名是审核通过的
					this.Censor(role.Name);

					//确认角色名是否存在
					if(this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_ROLE,
											  Condition.NotEqual("RoleId", role.RoleId) &
											  Condition.Equal("Name", role.Name) &
											  Condition.Equal("Namespace", MembershipHelper.TrimNamespace(role.Namespace))))
						throw new DataConflictException(Zongsoft.Resources.ResourceUtility.GetString("Text.RoleConflict"));
				}
			}

			return this.DataAccess.UpdateMany(MembershipHelper.DATA_ENTITY_ROLE, roles, scope);
		}
		#endregion

		#region 成员管理
		public bool InRole(int userId, int roleId)
		{
			//获取指定用户编号对应的用户名
			var userDictionary = this.DataAccess.Select<IDictionary>(MembershipHelper.DATA_ENTITY_USER, Condition.Equal("UserId", userId), "Name").FirstOrDefault();

			//如果指定的用户编号对应的是系统内置管理员（即 Administrator）则进行特殊处理，即系统内置管理员账号只能默认属于内置的管理员角色，它不能隶属于其它角色
			if(userDictionary != null && string.Equals((string)userDictionary["Name"], User.Administrator, StringComparison.OrdinalIgnoreCase))
			{
				//获取指定角色编号对应的角色名
				var roleDictionary = this.DataAccess.Select<IDictionary>(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("RoleId", roleId), "Name").FirstOrDefault();
				//如果指定的角色编号对应的是系统内置管理员角色（即 Administrators）则返回真，否则一律返回假。
				return (roleDictionary != null && string.Equals((string)roleDictionary["Name"], Role.Administrators, StringComparison.OrdinalIgnoreCase));
			}

			//处理非系统内置管理员账号
			return this.GetRecursiveRoles(userId, MemberType.User).Any(p => p.Item1 == roleId);
		}

		public bool InRoles(int userId, params string[] roleNames)
		{
			if(roleNames == null || roleNames.Length < 1)
				return false;

			//获取指定用户编号对应的用户名
			var userDictionary = this.DataAccess.Select<IDictionary>(MembershipHelper.DATA_ENTITY_USER, Condition.Equal("UserId", userId), "Name").FirstOrDefault();

			//如果指定的用户编号对应的是系统内置管理员（即 Administrator）则进行特殊处理，即系统内置管理员账号只能默认属于内置的管理员角色，它不能隶属于其它角色
			if(userDictionary != null && string.Equals((string)userDictionary["Name"], User.Administrator, StringComparison.OrdinalIgnoreCase))
				return roleNames.Contains(Role.Administrators, StringComparer.OrdinalIgnoreCase);

			//处理非系统内置管理员账号
			return this.GetRecursiveRoles(userId, MemberType.User).Any(p => roleNames.Contains(p.Item2, StringComparer.OrdinalIgnoreCase));
		}

		public IEnumerable<Role> GetRoles(int memberId, MemberType memberType)
		{
			var members = this.DataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER,
														 Condition.Equal("MemberId", memberId) & Condition.Equal("MemberType", memberType),
														 "Role");

			return members.Select(m => m.Role);
		}

		public IEnumerable<Member> GetMembers(int roleId)
		{
			//查出指定角色的所有子级成员
			var members = this.DataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER, new Condition("RoleId", roleId), "Role");

			//从数据库中查找当前子级成员中的角色成员
			var roles = this.DataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, Condition.In("RoleId", members.Where(m => m.MemberType == MemberType.Role).Select(m => m.MemberId)));
			//从数据库中查找当前子级成员中的用户成员
			var users = this.DataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, Condition.In("UserId", members.Where(m => m.MemberType == MemberType.User).Select(m => m.MemberId)));

			foreach(var member in members)
			{
				switch(member.MemberType)
				{
					case MemberType.Role:
						member.MemberObject = roles.FirstOrDefault(p => p.RoleId == member.MemberId);
						break;
					case MemberType.User:
						member.MemberObject = users.FirstOrDefault(p => p.UserId == member.MemberId);
						break;
				}
			}

			return members;
		}

		public int SetMembers(int roleId, params Member[] members)
		{
			return this.SetMembers(roleId, members, false);
		}

		public int SetMembers(int roleId, IEnumerable<Member> members, bool shouldResetting = false)
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

				foreach(var member in members)
				{
					if(member == null)
						continue;

					//更新成员的角色编号
					member.RoleId = roleId;

					bool existed;

					if(member.MemberType == MemberType.Role)
						existed = this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("RoleId", member.MemberId));
					else
						existed = this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, Condition.Equal("UserId", member.MemberId));

					if(existed)
					{
						//插入指定的角色成员集到数据库中
						count += this.DataAccess.Insert(MembershipHelper.DATA_ENTITY_MEMBER, member);
					}
				}

				//提交事务
				transaction.Commit();
			}

			return count;
		}

		public int DeleteMembers(params Member[] members)
		{
			if(members == null || members.Length < 1)
				return 0;

			return this.DeleteMembers((IEnumerable<Member>)members);
		}

		public int DeleteMembers(IEnumerable<Member> members)
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
						Condition.Equal("RoleId", member.RoleId) &
						Condition.Equal("MemberId", member.MemberId) &
						Condition.Equal("MemberType", member.MemberType));
				}

				return count;
			}
		}

		public int CreateMembers(params Member[] members)
		{
			if(members == null || members.Length < 1)
				return 0;

			return this.CreateMembers((IEnumerable<Member>)members);
		}

		public int CreateMembers(IEnumerable<Member> members)
		{
			if(members == null)
				return 0;

			return this.DataAccess.InsertMany(MembershipHelper.DATA_ENTITY_MEMBER, members);
		}
		#endregion

		#region 私有方法
		private void Censor(string name)
		{
			var censorship = this.Censorship;

			if(censorship != null && censorship.IsBlocked(name, Zongsoft.Security.Censorship.KEY_NAMES, Zongsoft.Security.Censorship.KEY_SENSITIVES))
				throw new CensorshipException(string.Format("Illegal '{0}' name of role.", name));
		}

		private IEnumerable<Tuple<int, string>> GetRecursiveRoles(int memberId, MemberType memberType)
		{
			var parents = this.DataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER,
														 Condition.Equal("MemberId", memberId) & Condition.Equal("MemberType", memberType),
														 "Role.RoleId, Role.Name");

			var result = new List<Tuple<int, string>>();
			result.AddRange(parents.Select(p => new Tuple<int, string>(p.RoleId, p.Role.Name)));

			int index = 0;

			while(index < result.Count)
			{
				parents = this.DataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER,
														 Condition.Equal("MemberId", result[index]) & Condition.Equal("MemberType", MemberType.Role),
														 "Role.RoleId, Role.Name");

				result.AddRange(parents.Where(p => !result.Exists(it => it.Item1 == p.RoleId)).Select(p => new Tuple<int, string>(p.RoleId, p.Role.Name)));

				index++;
			}

			return result;
		}
		#endregion
	}
}
