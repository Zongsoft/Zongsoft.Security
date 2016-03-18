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
using System.Text.RegularExpressions;

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
		public static bool GetPassword(IDataAccess dataAccess, int userId, out byte[] password, out byte[] passwordSalt, out bool isApproved, out bool isSuspended)
		{
			return GetPasswordCore(dataAccess, new Condition("UserId", userId), out password, out passwordSalt, out isApproved, out isSuspended) != 0;
		}

		public static int? GetPassword(IDataAccess dataAccess, string identity, string @namespace, out byte[] password, out byte[] passwordSalt, out bool isApproved, out bool isSuspended)
		{
			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			return GetPasswordCore(dataAccess, condition, out password, out passwordSalt, out isApproved, out isSuspended);
		}

		public static User GetUser(IDataAccess dataAccess, int userId)
		{
			if(dataAccess == null)
				throw new ArgumentNullException("dataAccess");

			return dataAccess.Select<User>(DATA_ENTITY_USER, new Condition("UserId", userId)).FirstOrDefault();
		}

		public static bool GetUserId(IDataAccess dataAccess, string identity, string @namespace, out int userId)
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
				userId = Zongsoft.Common.Convert.ConvertValue<int>(record["UserId"]);

			return result;
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

			string text;
			Condition condition;

			if(Zongsoft.Text.TextRegular.Web.Email.IsMatch(identity, out text))
			{
				identityType = UserIdentityType.Email;
				condition = Condition.Equal("Email", text);
			}
			else if(Zongsoft.Text.TextRegular.Chinese.Cellphone.IsMatch(identity, out text))
			{
				identityType = UserIdentityType.Phone;
				condition = Condition.Equal("PhoneNumber", text);
			}
			else
			{
				identityType = UserIdentityType.Name;
				condition = Condition.Equal("Name", identity);
			}

			return condition & Condition.Equal("Namespace", TrimNamespace(@namespace));
		}

		internal static string TrimNamespace(string @namespace)
		{
			return string.IsNullOrWhiteSpace(@namespace) ? null : @namespace.Trim();
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
							flag = !string.Equals(part.Substring(1), memberName, StringComparison.OrdinalIgnoreCase);
						else
							flag = string.Equals(part, memberName, StringComparison.OrdinalIgnoreCase);
						break;
				}
			}

			if(flag.HasValue)
				return flag.Value;

			return System.ComponentModel.TypeDescriptor.GetProperties(typeof(T)).Find(memberName, true) != null;
		}
		#endregion

		#region 私有方法
		private static int? GetPasswordCore(IDataAccess dataAccess, ICondition condition, out byte[] password, out byte[] passwordSalt, out bool isApproved, out bool isSuspended)
		{
			if(dataAccess == null)
				throw new ArgumentNullException("dataAccess");

			if(condition == null)
				throw new ArgumentNullException("condition");

			password = null;
			passwordSalt = null;
			isApproved = false;
			isSuspended = false;

			//从数据引擎中获取指定条件的用户密码数据
			var dictionary = dataAccess.Select<IDictionary<string, object>>(MembershipHelper.DATA_ENTITY_USER, condition, "!, UserId, Password, PasswordSalt, Approved, Suspended").FirstOrDefault();

			if(dictionary == null || dictionary.Count < 1)
				return null;

			object value;

			if(dictionary.TryGetValue("Approved", out value))
				isApproved = Zongsoft.Common.Convert.ConvertValue<bool>(value);

			if(dictionary.TryGetValue("Suspended", out value))
				isSuspended = Zongsoft.Common.Convert.ConvertValue<bool>(value);

			object storedPassword;
			object storedPasswordSalt;

			dictionary.TryGetValue("Password", out storedPassword);
			dictionary.TryGetValue("PasswordSalt", out storedPasswordSalt);

			password = storedPassword as byte[];
			passwordSalt = storedPasswordSalt as byte[];

			object result;

			if(dictionary.TryGetValue("UserId", out result))
				return Zongsoft.Common.Convert.ConvertValue<int?>(result, () => null);

			return null;
		}
		#endregion
	}
}
