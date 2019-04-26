/*
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@gmail.com>
 *
 * Copyright (C) 2010-2016 Zongsoft Corporation <http://www.zongsoft.com>
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

namespace Zongsoft.Security.Membership
{
	internal static class MembershipHelper
	{
		#region 常量定义
		internal const string Administrator = "Administrator";
		internal const string Administrators = "Administrators";
		#endregion

		#region 公共方法
		/// <summary>
		/// 获取指定用户或角色的上级角色集。
		/// </summary>
		/// <param name="dataAccess">数据访问服务。</param>
		/// <param name="memberId">成员编号（用户或角色）。</param>
		/// <param name="memberType">成员类型，表示<paramref name="memberId"/>对应的成员类型。</param>
		/// <param name="flats">输出参数，表示所隶属的所有上级角色集，该集已经去除重复。</param>
		/// <param name="hierarchies">输出参数，表示所隶属的所有上级角色的层级列表，该列表包含的所有角色已经去除重复。</param>
		/// <returns>返回指定成员隶属的所有上级角色去重后的数量。</returns>
		public static int GetAncestors(IDataAccess dataAccess, uint memberId, MemberType memberType, out ISet<IRole> flats, out IList<IEnumerable<IRole>> hierarchies)
		{
			if(dataAccess == null)
				throw new ArgumentNullException(nameof(dataAccess));

			flats = null;
			hierarchies = null;

			//指定成员的所属命名空间
			string @namespace = null;

			if(memberType == MemberType.User)
			{
				//获取指定编号的用户对象
				var user = dataAccess.Select<IUser>(Condition.Equal(nameof(IUser.UserId), memberId), "!, UserId, Name, Namespace").FirstOrDefault();

				//如果指定编号的用户不存在，则退出
				if(user == null)
					return 0;

				//如果指定编号的用户是内置的“Administrator”账号，则直接返回（因为内置管理员只隶属于内置的“Administrators”角色，而不能属于其他角色）
				if(string.Equals(user.Name, Administrator, StringComparison.OrdinalIgnoreCase))
				{
					//获取当前用户同命名空间下的“Administrators”内置角色
					flats = new HashSet<IRole>(dataAccess.Select<IRole>(Condition.Equal(nameof(IRole.Name), Administrators) & Condition.Equal(nameof(IRole.Namespace), user.Namespace)));

					if(flats.Count > 0)
					{
						hierarchies = new List<IEnumerable<IRole>>();
						hierarchies.Add(flats);
					}

					//返回（零或者一）
					return flats.Count;
				}

				@namespace = user.Namespace;
			}
			else
			{
				//获取指定编号的角色对象
				var role = dataAccess.Select<IRole>(Condition.Equal(nameof(IRole.RoleId), memberId), "!, RoleId, Name, Namespace").FirstOrDefault();

				//如果指定编号的角色不存在或是一个内置角色（内置角色没有归属），则退出
				if(role == null || IsBuiltin(role.Name))
					return 0;

				@namespace = role.Namespace;
			}

			//获取指定用户所属命名空间下的所有成员及其关联的角色对象（注：即时加载到内存中）
			var members = dataAccess.Select<Member>(Condition.Equal("Role.Namespace", @namespace), "*, Role{*}")
			                        .Where(m => m.Role != null)
			                        .ToArray();

			flats = new HashSet<IRole>();
			hierarchies = new List<IEnumerable<IRole>>();

			//从角色成员集合中查找出指定成员的父级角色
			var parents = members.Where(m => m.MemberId == memberId && m.MemberType == memberType)
			                     .Select(m => m.Role).ToArray();

			//如果父级角色集不为空
			while(parents.Any())
			{
				//将父角色集合并到输出参数中
				flats.UnionWith(parents);
				//将特定层级的所有父角色集加入到层级列表中
				hierarchies.Add(parents);

				//从角色成员集合中查找出当前层级中所有角色的父级角色集合（并进行全局去重）
				parents = members.Where(m => parents.Any(p => p.RoleId == m.MemberId) && m.MemberType == MemberType.Role)
				                 .Select(m => m.Role)
				                 .Except(flats).ToArray();
			}

			return flats.Count;
		}
		#endregion

		#region 内部方法
		internal static Condition GetUserIdentity(string identity)
		{
			return GetUserIdentity(identity, out _);
		}

		internal static Condition GetUserIdentity(string identity, out UserIdentityType identityType)
		{
			if(string.IsNullOrWhiteSpace(identity))
				throw new ArgumentNullException(nameof(identity));

			if(identity.Contains("@"))
			{
				identityType = UserIdentityType.Email;
				return Condition.Equal(nameof(IUser.Email), identity);
			}

			if(IsNumericString(identity))
			{
				identityType = UserIdentityType.PhoneNumber;
				return Condition.Equal(nameof(IUser.PhoneNumber), identity);
			}

			identityType = UserIdentityType.Name;
			return Condition.Equal(nameof(IUser.Name), identity);
		}
		#endregion

		#region 私有方法
		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private static bool IsNumericString(string text)
		{
			if(string.IsNullOrEmpty(text))
				return false;

			for(var i = 0; i < text.Length; i++)
			{
				if(text[i] < '0' || text[i] > '9')
					return false;
			}

			return true;
		}

		private static bool IsBuiltin(string name)
		{
			return string.Equals(name, Administrator, StringComparison.OrdinalIgnoreCase) ||
			       string.Equals(name, Administrators, StringComparison.OrdinalIgnoreCase);
		}
		#endregion
	}
}
