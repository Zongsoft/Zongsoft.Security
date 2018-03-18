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
using System.Collections.Generic;
using System.Linq;

using Zongsoft.Data;

namespace Zongsoft.Security.Membership
{
	internal static class MembershipHelper
	{
		#region 枚举定义
		internal enum UserIdentityType
		{
			Name,
			Phone,
			Email,
		}
		#endregion

		#region 常量定义
		internal const string DATA_CONTAINER_NAME = "Security";

		internal const string DATA_COMMAND_GETROLES = DATA_CONTAINER_NAME + ".GetRoles";
		internal const string DATA_COMMAND_GETMEMBERS = DATA_CONTAINER_NAME + ".GetMembers";

		internal const string DATA_ENTITY_USER = DATA_CONTAINER_NAME + ".User";
		internal const string DATA_ENTITY_ROLE = DATA_CONTAINER_NAME + ".Role";
		internal const string DATA_ENTITY_MEMBER = DATA_CONTAINER_NAME + ".Member";
		internal const string DATA_ENTITY_PERMISSION = DATA_CONTAINER_NAME + ".Permission";
		internal const string DATA_ENTITY_PERMISSION_FILTER = DATA_CONTAINER_NAME + ".PermissionFilter";

		internal const int MINIMUM_ID = 100000;

		internal const string SEQUENCE_USERID = "Zongsoft.Security.Membership.User.ID";
		internal const string SEQUENCE_ROLEID = "Zongsoft.Security.Membership.Role.ID";
		#endregion

		#region 公共方法
		public static bool GetPassword(IDataAccess dataAccess, uint userId, out byte[] password, out byte[] passwordSalt)
		{
			UserStatus status;
			DateTime? statusTimestamp;

			return GetPasswordCore(dataAccess, Condition.Equal("UserId", userId), out password, out passwordSalt, out status, out statusTimestamp) > 0;
		}

		public static bool GetPassword(IDataAccess dataAccess, uint userId, out byte[] password, out byte[] passwordSalt, out UserStatus status, out DateTime? statusTimestamp)
		{
			return GetPasswordCore(dataAccess, Condition.Equal("UserId", userId), out password, out passwordSalt, out status, out statusTimestamp) > 0;
		}

		public static uint? GetPassword(IDataAccess dataAccess, string identity, string @namespace, out byte[] password, out byte[] passwordSalt)
		{
			UserStatus status;
			DateTime? statusTimestamp;

			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			return GetPasswordCore(dataAccess, condition, out password, out passwordSalt, out status, out statusTimestamp);
		}

		public static uint? GetPassword(IDataAccess dataAccess, string identity, string @namespace, out byte[] password, out byte[] passwordSalt, out UserStatus status, out DateTime? statusTimestamp)
		{
			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			return GetPasswordCore(dataAccess, condition, out password, out passwordSalt, out status, out statusTimestamp);
		}

		public static User GetUser(IDataAccess dataAccess, uint userId)
		{
			if(dataAccess == null)
				throw new ArgumentNullException("dataAccess");

			return dataAccess.Select<User>(DATA_ENTITY_USER, Condition.Equal("UserId", userId), "!Password, !PasswordSalt").FirstOrDefault();
		}

		public static bool GetUserId(IDataAccess dataAccess, string identity, string @namespace, out uint userId)
		{
			if(dataAccess == null)
				throw new ArgumentNullException("dataAccess");

			if(string.IsNullOrWhiteSpace(identity))
				throw new ArgumentNullException("identity");

			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			var record = dataAccess.Select<IDictionary<string, object>>(MembershipHelper.DATA_ENTITY_USER, condition, "!, UserId").FirstOrDefault();
			var result = record != null && record.Count > 0 && record.ContainsKey("UserId");

			userId = 0;

			if(result)
				userId = Zongsoft.Common.Convert.ConvertValue<uint>(record["UserId"]);

			return result;
		}

		/// <summary>
		/// 获取指定用户或角色的上级角色集。
		/// </summary>
		/// <param name="dataAccess">数据访问服务。</param>
		/// <param name="memberId">成员编号（用户或角色）。</param>
		/// <param name="memberType">成员类型，表示<paramref name="memberId"/>对应的成员类型。</param>
		/// <param name="flats">输出参数，表示所隶属的所有上级角色集，该集已经去除重复。</param>
		/// <param name="hierarchies">输出参数，表示所隶属的所有上级角色的层级列表，该列表包含的所有角色已经去除重复。</param>
		/// <returns>返回指定成员隶属的所有上级角色去重后的数量。</returns>
		public static int GetAncestors(IDataAccess dataAccess, uint memberId, MemberType memberType, out ISet<Role> flats, out IList<IEnumerable<Role>> hierarchies)
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
				var user = dataAccess.Select<User>(DATA_ENTITY_USER, Condition.Equal("UserId", memberId), "!, UserId, Name, Namespace").FirstOrDefault();

				//如果指定编号的用户不存在，则退出
				if(user == null)
					return 0;

				//如果指定编号的用户是内置的“Administrator”账号，则直接返回（因为内置管理员只隶属于内置的“Administrators”角色，而不能属于其他角色）
				if(string.Equals(user.Name, User.Administrator, StringComparison.OrdinalIgnoreCase))
				{
					//获取当前用户同命名空间下的“Administrators”内置角色
					flats = new HashSet<Role>(dataAccess.Select<Role>(DATA_ENTITY_ROLE, Condition.Equal("Name", Role.Administrators) & Condition.Equal("Namespace", user.Namespace)));

					if(flats.Count > 0)
					{
						hierarchies = new List<IEnumerable<Role>>();
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
				var role = dataAccess.Select<Role>(DATA_ENTITY_ROLE, Condition.Equal("RoleId", memberId), "!, RoleId, Name, Namespace").FirstOrDefault();

				//如果指定编号的角色不存在或是一个内置角色（内置角色没有归属），则退出
				if(role == null || Role.IsBuiltin(role))
					return 0;

				@namespace = role.Namespace;
			}

			//获取指定用户所属命名空间下的所有角色（注：禁止分页查询，并即时加载到数组中）
			var roles = dataAccess.Select<Role>(DATA_ENTITY_ROLE, Condition.Equal("Namespace", @namespace), Paging.Disable).ToArray();

			//获取指定用户所属命名空间下的所有角色成员定义（注：禁止分页查询，并即时加载到数组中）
			var members = dataAccess.Select<Member>(DATA_ENTITY_MEMBER, Condition.In("RoleId", roles.Select(p => p.RoleId)), Paging.Disable).ToArray();

			flats = new HashSet<Role>();
			hierarchies = new List<IEnumerable<Role>>();

			//从角色成员集合中查找出指定成员的父级角色
			var parents = members.Where(m => m.MemberId == memberId && m.MemberType == memberType)
			                     .Select(m => roles.FirstOrDefault(role => role.RoleId == m.RoleId))
			                     .ToArray();

			//如果父级角色集不为空
			while(parents.Any())
			{
				//将父角色集合并到输出参数中
				flats.UnionWith(parents);
				//将特定层级的所有父角色集加入到层级列表中
				hierarchies.Add(parents);

				//从角色成员集合中查找出当前层级中所有角色的父级角色集合（并进行全局去重）
				parents = members.Where(m => parents.Any(p => p.RoleId == m.MemberId) && m.MemberType == MemberType.Role)
				                 .Select(m => roles.FirstOrDefault(role => role.RoleId == m.RoleId))
				                 .Except(flats).ToArray();
			}

			return flats.Count;
		}
		#endregion

		#region 内部方法
		internal static ICondition GetUserIdentityCondition(string identity, string @namespace)
		{
			UserIdentityType identityType;
			return GetUserIdentityCondition(identity, @namespace, out identityType);
		}

		internal static ICondition GetUserIdentityCondition(string identity, string @namespace, out UserIdentityType identityType)
		{
			if(string.IsNullOrWhiteSpace(identity))
				throw new ArgumentNullException("identity");

			Condition condition;

			if(identity.Contains("@"))
			{
				identityType = UserIdentityType.Email;
				condition = Condition.Equal("Email", identity);
			}
			else if(IsNumericString(identity))
			{
				identityType = UserIdentityType.Phone;
				condition = Condition.Equal("PhoneNumber", identity);
			}
			else
			{
				identityType = UserIdentityType.Name;
				condition = Condition.Equal("Name", identity);
			}

			//string text;

			//if(Zongsoft.Text.TextRegular.Web.Email.IsMatch(identity, out text))
			//{
			//	identityType = UserIdentityType.Email;
			//	condition = Condition.Equal("Email", text);
			//}
			//else if(Zongsoft.Text.TextRegular.Chinese.Cellphone.IsMatch(identity, out text))
			//{
			//	identityType = UserIdentityType.Phone;
			//	condition = Condition.Equal("PhoneNumber", text);
			//}
			//else
			//{
			//	identityType = UserIdentityType.Name;
			//	condition = Condition.Equal("Name", identity);
			//}

			return condition & GetNamespaceCondition(@namespace);
		}

		internal static Condition GetNamespaceCondition(string @namespace)
		{
			if(string.IsNullOrWhiteSpace(@namespace))
				return Condition.Equal("Namespace", null);

			@namespace = @namespace.Trim();

			if(@namespace == "*")
				return null;

			if(@namespace.Contains('*') || @namespace.Contains('?'))
				return Condition.Like("Namespace", @namespace.Replace('*', '%').Replace('?', '_'));

			return Condition.Equal("Namespace", @namespace);
		}

		internal static bool InScope<T>(string scope, string memberName)
		{
			if(string.IsNullOrWhiteSpace(memberName))
				throw new ArgumentNullException("memberName");

			if(string.IsNullOrWhiteSpace(scope))
				return true;

			bool? flag = null;
			var parts = scope.Split(',', ';');

			for(int i = 0; i < parts.Length; i++)
			{
				var part = parts[i].Trim();

				if(part.Length == 0)
					continue;

				switch(part)
				{
					case "-":
					case "!":
						flag = false;
						break;
					case "*":
						flag = true;
						break;
					default:
						if(part[0] == '!' || part[0] == '-')
						{
							if(string.Equals(part.Substring(1), memberName, StringComparison.OrdinalIgnoreCase))
								flag = false;
						}
						else
						{
							if(string.Equals(part, memberName, StringComparison.OrdinalIgnoreCase))
								flag = true;
						}
						break;
				}
			}

			if(flag.HasValue)
				return flag.Value;

			return System.ComponentModel.TypeDescriptor.GetProperties(typeof(T)).Find(memberName, true) != null;
		}

		internal static bool EnsureCurrentUserId(out uint userId)
		{
			userId = 0;

			var principal = Zongsoft.ComponentModel.ApplicationContextBase.Current?.Principal as CredentialPrincipal;

			if(principal != null && principal.Identity != null && principal.Identity.IsAuthenticated && principal.Identity.Credential != null)
			{
				userId = principal.Identity.Credential.UserId;
				return true;
			}

			return false;
		}
		#endregion

		#region 私有方法
		private static uint? GetPasswordCore(IDataAccess dataAccess, ICondition condition, out byte[] password, out byte[] passwordSalt, out UserStatus status, out DateTime? statusTimestamp)
		{
			if(dataAccess == null)
				throw new ArgumentNullException("dataAccess");

			if(condition == null)
				throw new ArgumentNullException("condition");

			password = null;
			passwordSalt = null;
			status = UserStatus.Active;
			statusTimestamp = null;

			//从数据引擎中获取指定条件的用户密码数据
			var dictionary = dataAccess.Select<IDictionary<string, object>>(MembershipHelper.DATA_ENTITY_USER, condition, "!, UserId, Password, PasswordSalt, Status, StatusTimestamp").FirstOrDefault();

			if(dictionary == null || dictionary.Count < 1)
				return null;

			object value;

			if(dictionary.TryGetValue("Status", out value))
				status = Zongsoft.Common.Convert.ConvertValue<UserStatus>(value);

			if(dictionary.TryGetValue("StatusTimestamp", out value))
				statusTimestamp = Zongsoft.Common.Convert.ConvertValue<DateTime?>(value);

			object storedPassword;
			object storedPasswordSalt;

			dictionary.TryGetValue("Password", out storedPassword);
			dictionary.TryGetValue("PasswordSalt", out storedPasswordSalt);

			password = storedPassword as byte[];
			passwordSalt = storedPasswordSalt as byte[];

			object result;

			if(dictionary.TryGetValue("UserId", out result))
				return Zongsoft.Common.Convert.ConvertValue<uint?>(result, () => null);

			return null;
		}

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
		#endregion
	}
}
