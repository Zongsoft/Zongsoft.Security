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
		#region 常量定义
		internal const string DATA_CONTAINER_NAME = "Security";

		internal const string DATA_COMMAND_GETROLES = DATA_CONTAINER_NAME + ".GetRoles";
		internal const string DATA_COMMAND_GETMEMBERS = DATA_CONTAINER_NAME + ".GetMembers";

		internal const string DATA_ENTITY_USER = DATA_CONTAINER_NAME + ".User";
		internal const string DATA_ENTITY_ROLE = DATA_CONTAINER_NAME + ".Role";
		internal const string DATA_ENTITY_MEMBER = DATA_CONTAINER_NAME + ".Member";
		internal const string DATA_ENTITY_PERMISSION = DATA_CONTAINER_NAME + ".Permission";
		internal const string DATA_ENTITY_PERMISSION_FILTER = DATA_CONTAINER_NAME + ".PermissionFilter";
		#endregion

		#region 公共方法
		public static bool GetPassword(IDataAccess dataAccess, int userId, out byte[] password, out byte[] passwordSalt)
		{
			return GetPasswordCore(dataAccess, new Condition("UserId", userId), out password, out passwordSalt) != 0;
		}

		public static int? GetPassword(IDataAccess dataAccess, string identity, string @namespace, out byte[] password, out byte[] passwordSalt)
		{
			var conditions = new ConditionCollection(ConditionCombine.And, MembershipHelper.GetUserIdentityConditions(identity, @namespace));
			return GetPasswordCore(dataAccess, conditions, out password, out passwordSalt);
		}

		public static User GetUser(IDataAccess dataAccess, int userId)
		{
			if(dataAccess == null)
				throw new ArgumentNullException("dataAccess");

			return dataAccess.Select<User>(DATA_ENTITY_USER, new Condition("UserId", userId)).FirstOrDefault();
		}
		#endregion

		#region 内部方法
		internal static Condition[] GetUserIdentityConditions(string identity, string @namespace)
		{
			if(string.IsNullOrWhiteSpace(identity))
				throw new ArgumentNullException("identity");

			var conditions = new Condition[2];
			conditions[0] = new Condition("Namespace", TrimNamespace(@namespace));

			if(Zongsoft.Text.TextRegular.Web.Email.IsMatch(identity, out identity))
				conditions[1] = new Condition("Email", identity);
			else if(Zongsoft.Text.TextRegular.Chinese.Cellphone.IsMatch(identity, out identity))
				conditions[1] = new Condition("PhoneNumber", identity);
			else
				conditions[1] = new Condition("Name", identity);

			return conditions;
		}

		internal static string TrimNamespace(string @namespace)
		{
			return string.IsNullOrWhiteSpace(@namespace) ? null : @namespace.Trim();
		}

		internal static void EnsureName(string name)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new InvalidOperationException("The value of 'Name' property cann't is null or empty.");

			name = name.Trim();

			if(name.Length < 2)
				throw new InvalidOperationException("The value of 'Name' property length must greater than 1.");

			if(!((name[1] >= 'A' && name[1] <= 'Z') || (name[1] >= 'a' && name[1] <= 'z')))
				throw new InvalidOperationException("The value of 'Name' property first character must is letters of an alphabet");

			if(Censorship.Names.IsBlocked(name))
				throw new InvalidOperationException(string.Format("The '{0}' name is blocked.", name));
		}
		#endregion

		#region 私有方法
		private static int? GetPasswordCore(IDataAccess dataAccess, ICondition condition, out byte[] password, out byte[] passwordSalt)
		{
			if(dataAccess == null)
				throw new ArgumentNullException("dataAccess");

			if(condition == null)
				throw new ArgumentNullException("condition");

			password = null;
			passwordSalt = null;

			//从数据引擎中获取指定条件的用户密码数据
			var dictionary = dataAccess.Select<IDictionary<string, object>>(MembershipHelper.DATA_ENTITY_USER, condition, "!, UserId, Password, PasswordSalt").FirstOrDefault();

			if(dictionary == null)
				return null;

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
