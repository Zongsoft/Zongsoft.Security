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
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Zongsoft.Data;
using Zongsoft.Options;

namespace Zongsoft.Security.Membership
{
	public class RoleProvider : MembershipProviderBase, IRoleProvider, IMemberProvider
	{
		#region 构造函数
		public RoleProvider()
		{
		}
		#endregion

		#region 角色管理
		public Role GetRole(int roleId)
		{
			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, new Condition("RoleId", roleId)).FirstOrDefault();
		}

		public IEnumerable<Role> GetAllRoles(string @namespace, Paging paging = null)
		{
			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, new Condition("Namespace", MembershipHelper.TrimNamespace(@namespace)), null, paging ?? new Paging(1, 20));
		}

		public int DeleteRoles(params int[] roleIds)
		{
			if(roleIds == null || roleIds.Length < 1)
				return 0;

			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Delete(MembershipHelper.DATA_ENTITY_ROLE, new Condition("RoleId", roleIds, ConditionOperator.In));
		}

		public int CreateRoles(params Role[] roles)
		{
			return this.CreateRoles((IEnumerable<Role>)roles);
		}

		public int CreateRoles(IEnumerable<Role> roles)
		{
			if(roles == null)
				return 0;

			foreach(var role in roles)
			{
				//确保所有角色名是有效的
				MembershipHelper.EnsureName(role.Name);
			}

			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Insert(MembershipHelper.DATA_ENTITY_ROLE, roles);
		}

		public int UpdateRoles(params Role[] roles)
		{
			return this.UpdateRoles((IEnumerable<Role>)roles);
		}

		public int UpdateRoles(IEnumerable<Role> roles)
		{
			if(roles == null)
				return 0;

			foreach(var role in roles)
			{
				//确保所有角色名是有效的
				MembershipHelper.EnsureName(role.Name);
			}

			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Update(MembershipHelper.DATA_ENTITY_ROLE, roles);
		}
		#endregion

		#region 成员管理
		public bool InRole(int userId, int roleId)
		{
			return this.GetRoles(userId, MemberType.User, -1).Any(role => role.RoleId == roleId);
		}

		public IEnumerable<Role> GetRoles(int memberId, MemberType memberType)
		{
			var dataAccess = this.EnsureDataAccess();

			var members = dataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER, new ConditionCollection(ConditionCombine.And, new Condition[] {
				new Condition("MemberId", memberId),
				new Condition("MemberType", memberType),
			}), "Role");

			return members.Select(m => m.Role);
		}

		public IEnumerable<Role> GetRoles(int memberId, MemberType memberType, int depth)
		{
			throw new NotImplementedException();
		}

		public IEnumerable<Member> GetMembers(int roleId)
		{
			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Select<Member>(MembershipHelper.DATA_ENTITY_MEMBER, new Condition("RoleId", roleId));
		}

		public IEnumerable<Member> GetMembers(int roleId, int depth)
		{
			throw new NotImplementedException();
		}

		public void SetMembers(int roleId, IEnumerable<Member> members)
		{
			if(members == null)
				return;

			var dataAccess = this.EnsureDataAccess();

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
			return this.DeleteMembers((IEnumerable<Member>)members);
		}

		public int DeleteMembers(IEnumerable<Member> members)
		{
			if(members == null)
				return 0;

			var dataAccess = this.EnsureDataAccess();

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
			return this.CreateMembers((IEnumerable<Member>)members);
		}

		public int CreateMembers(IEnumerable<Member> members)
		{
			if(members == null)
				return 0;

			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Insert(MembershipHelper.DATA_ENTITY_MEMBER, members);
		}
		#endregion
	}
}
