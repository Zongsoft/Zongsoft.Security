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

		public IEnumerable<Role> GetAllRoles(string @namespace)
		{
			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Select<Role>(MembershipHelper.DATA_ENTITY_ROLE, new Condition("Namespace", MembershipHelper.TrimNamespace(@namespace)));
		}

		public IEnumerable<Role> GetRoles(int memberId, MemberType memberType)
		{
			var dataAccess = this.EnsureDataAccess();

			var roles = dataAccess.Execute(MembershipHelper.DATA_ENTITY_ROLE, new Dictionary<string, object>
			{
				{"MemberId", memberId},
				{"MemberType", memberType},
			}) as IEnumerable<Role>;

			return roles;
		}

		public IEnumerable<Role> GetRoles(int memberId, MemberType memberType, int depth)
		{
			throw new NotImplementedException();
		}

		public int DeleteRoles(params int[] roleIds)
		{
			if(roleIds == null || roleIds.Length < 1)
				return 0;

			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Delete(MembershipHelper.DATA_ENTITY_ROLE, new Condition("RoleId", roleIds, ConditionOperator.In));
		}

		public void CreateRoles(IEnumerable<Role> roles)
		{
			if(roles == null)
				return;

			var dataAccess = this.EnsureDataAccess();
			dataAccess.Insert(MembershipHelper.DATA_ENTITY_ROLE, roles);
		}

		public void UpdateRoles(IEnumerable<Role> roles)
		{
			if(roles == null)
				return;

			var dataAccess = this.EnsureDataAccess();
			dataAccess.Update(MembershipHelper.DATA_ENTITY_ROLE, roles);
		}
		#endregion

		#region 成员管理
		public bool InRole(int userId, int roleId)
		{
			return this.GetRoles(userId, MemberType.User, -1).Any(role => role.RoleId == roleId);
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

		public void DeleteMember(int roleId, int memberId, MemberType memberType)
		{
			var dataAccess = this.EnsureDataAccess();

			dataAccess.Delete(MembershipHelper.DATA_ENTITY_MEMBER, new ConditionCollection(ConditionCombine.And)
			{
				new Condition("RoleId", roleId),
				new Condition("MemberId", memberId),
				new Condition("MemberType", memberType),
			});
		}

		public void CreateMember(int roleId, int memberId, MemberType memberType)
		{
			var dataAccess = this.EnsureDataAccess();
			dataAccess.Insert(MembershipHelper.DATA_ENTITY_MEMBER, new Member(roleId, memberId, memberType));
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
		#endregion
	}
}
