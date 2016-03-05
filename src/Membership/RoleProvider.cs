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
using System.Linq;
using System.Text;

using Zongsoft.Data;
using Zongsoft.Options;

namespace Zongsoft.Security.Membership
{
	public class RoleProvider : Zongsoft.Services.ServiceBase, IRoleProvider, IMemberProvider
	{
		#region 成员字段
		private ICensorship _censorship;
		#endregion

		#region 构造函数
		public RoleProvider(Zongsoft.Services.IServiceProvider serviceProvider) : base(serviceProvider)
		{
		}
		#endregion

		#region 公共属性
		[Zongsoft.Services.Service]
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
		public Role GetRole(int roleId)
		{
			var dataAccess = this.EnsureService<IDataAccess>();
			return dataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, new Condition("RoleId", roleId)).FirstOrDefault();
		}

		public IEnumerable<Role> GetAllRoles(string @namespace, Paging paging = null)
		{
			var dataAccess = this.EnsureService<IDataAccess>();
			return dataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, Condition.Equal("Namespace", MembershipHelper.TrimNamespace(@namespace)), paging);
		}

		public int DeleteRoles(params int[] roleIds)
		{
			if(roleIds == null || roleIds.Length < 1)
				return 0;

			var dataAccess = this.EnsureService<IDataAccess>();
			return dataAccess.Delete(MembershipHelper.DATA_ENTITY_ROLE, new Condition("RoleId", roleIds, ConditionOperator.In));
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
			}

			foreach(var role in roles)
			{
				//处理未指定有效编号的角色对象
				if(role != null && role.RoleId < 1)
					role.RoleId = (int)this.EnsureService<Zongsoft.Common.ISequence>().GetSequenceNumber(MembershipHelper.SEQUENCE_ROLEID, 1, MembershipHelper.MINIMUM_ID);
			}

			var dataAccess = this.EnsureService<IDataAccess>();
			return dataAccess.Insert(MembershipHelper.DATA_ENTITY_ROLE, roles);
		}

		public int UpdateRoles(params Role[] roles)
		{
			if(roles == null || roles.Length < 1)
				return 0;

			return this.UpdateRoles((IEnumerable<Role>)roles);
		}

		public int UpdateRoles(IEnumerable<Role> roles)
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
			}

			var dataAccess = this.EnsureService<IDataAccess>();
			return dataAccess.Update(MembershipHelper.DATA_ENTITY_ROLE, roles);
		}
		#endregion

		#region 成员管理
		public bool InRole(int userId, int roleId)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			//获取指定用户编号对应的用户名
			var userDictionary = dataAccess.Select<IDictionary>(MembershipHelper.DATA_ENTITY_USER, new Condition("UserId", userId), "Name").FirstOrDefault();

			//如果指定的用户编号对应的是系统内置管理员（即 Administrator）则进行特殊处理，即系统内置管理员账号只能默认属于内置的管理员角色，它不能隶属于其它角色
			if(userDictionary != null && string.Equals((string)userDictionary["Name"], User.Administrator, StringComparison.OrdinalIgnoreCase))
			{
				//获取指定角色编号对应的角色名
				var roleDictionary = dataAccess.Select<IDictionary>(MembershipHelper.DATA_ENTITY_ROLE, new Condition("RoleId", roleId), "Name").FirstOrDefault();
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

			var dataAccess = this.EnsureService<IDataAccess>();

			//获取指定用户编号对应的用户名
			var userDictionary = dataAccess.Select<IDictionary>(MembershipHelper.DATA_ENTITY_USER, new Condition("UserId", userId), "Name").FirstOrDefault();

			//如果指定的用户编号对应的是系统内置管理员（即 Administrator）则进行特殊处理，即系统内置管理员账号只能默认属于内置的管理员角色，它不能隶属于其它角色
			if(userDictionary != null && string.Equals((string)userDictionary["Name"], User.Administrator, StringComparison.OrdinalIgnoreCase))
				return roleNames.Contains(Role.Administrators, StringComparer.OrdinalIgnoreCase);

			//处理非系统内置管理员账号
			return this.GetRecursiveRoles(userId, MemberType.User).Any(p => roleNames.Contains(p.Item2, StringComparer.OrdinalIgnoreCase));
		}

		public IEnumerable<Role> GetRoles(int memberId, MemberType memberType)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			var members = dataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER,
													new ConditionCollection(ConditionCombine.And, new Condition[] {
														new Condition("MemberId", memberId),
														new Condition("MemberType", memberType)}),
													"Role");

			return members.Select(m => m.Role);
		}

		public IEnumerable<Member> GetMembers(int roleId)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			//查出指定角色的所有子级成员
			var members = dataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER, new Condition("RoleId", roleId), "Role");

			//从数据库中查找当前子级成员中的角色成员
			var roles = dataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, new Condition("RoleId", members.Where(m => m.MemberType == MemberType.Role).Select(m => m.MemberId), ConditionOperator.In));
			//从数据库中查找当前子级成员中的用户成员
			var users = dataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, new Condition("UserId", members.Where(m => m.MemberType == MemberType.User).Select(m => m.MemberId), ConditionOperator.In));

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

		public void SetMembers(int roleId, IEnumerable<Member> members)
		{
			if(members == null)
				return;

			var dataAccess = this.EnsureService<IDataAccess>();

			foreach(var member in members)
			{
				member.RoleId = roleId;
			}

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				//清空指定角色的所有成员
				dataAccess.Delete(MembershipHelper.DATA_ENTITY_MEMBER, new Condition("RoleId", roleId));

				//插入指定的角色成员集到数据库中
				dataAccess.Insert(MembershipHelper.DATA_ENTITY_MEMBER, members);

				//提交事务
				transaction.Commit();
			}
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

			var dataAccess = this.EnsureService<IDataAccess>();

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				var count = 0;

				foreach(var member in members)
				{
					if(member == null)
						continue;

					count += dataAccess.Delete(MembershipHelper.DATA_ENTITY_MEMBER, new ConditionCollection(ConditionCombine.And)
					{
						new Condition("RoleId", member.RoleId),
						new Condition("MemberId", member.MemberId),
						new Condition("MemberType", member.MemberType),
					});
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

			var dataAccess = this.EnsureService<IDataAccess>();
			return dataAccess.Insert(MembershipHelper.DATA_ENTITY_MEMBER, members);
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
			var dataAccess = this.EnsureService<IDataAccess>();

			var parents = dataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER,
													new ConditionCollection(ConditionCombine.And, new Condition[] {
														new Condition("MemberId", memberId),
														new Condition("MemberType", memberType)}),
													"Role.RoleId, Role.Name");

			var result = new List<Tuple<int, string>>();
			result.AddRange(parents.Select(p => new Tuple<int, string>(p.RoleId, p.Role.Name)));

			int index = 0;

			while(index++ < result.Count)
			{
				parents = dataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER,
													new ConditionCollection(ConditionCombine.And, new Condition[] {
														new Condition("MemberId", result[index]),
														new Condition("MemberType", MemberType.Role)}),
													"Role.RoleId, Role.Name");

				result.AddRange(parents.Where(p => !result.Exists(it => it.Item1 == p.RoleId)).Select(p => new Tuple<int, string>(p.RoleId, p.Role.Name)));
			}

			return result;
		}
		#endregion
	}
}
