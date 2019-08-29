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

		public ISequence Sequence
		{
			get => _dataAccess?.Sequence;
		}

		public Credential Credential
		{
			get
			{
				if(ApplicationContext.Current == null || ApplicationContext.Current.Principal.Identity.IsAuthenticated == false)
					throw new AuthorizationException("No authorization or access to current user credentials.");

				var principal = ApplicationContext.Current.Principal as CredentialPrincipal ??
					throw new InvalidOperationException($"The '{ApplicationContext.Current.Principal.GetType().FullName}' is an invalid or unsupported type of security principal.");

				return principal.Identity.Credential;
			}
		}
		#endregion

		#region 角色管理
		public IRole GetRole(uint roleId)
		{
			return this.DataAccess.Select<IRole>(Condition.Equal(nameof(IRole.RoleId), roleId)).FirstOrDefault();
		}

		public IRole GetRole(string name, string @namespace = null)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new ArgumentNullException(nameof(name));

			return this.DataAccess.Select<IRole>(Condition.Equal(nameof(IRole.Name), name) & this.GetNamespace(@namespace)).FirstOrDefault();
		}

		public IEnumerable<IRole> GetRoles(string @namespace, Paging paging = null)
		{
			return this.DataAccess.Select<IRole>(this.GetNamespace(@namespace), paging);
		}

		public bool Exists(uint roleId)
		{
			return this.DataAccess.Exists<IRole>(Condition.Equal(nameof(IRole.RoleId), roleId));
		}

		public bool Exists(string name, string @namespace = null)
		{
			if(string.IsNullOrWhiteSpace(name))
				return false;

			return this.DataAccess.Exists<IRole>(Condition.Equal(nameof(IRole.Name), name) & this.GetNamespace(@namespace));
		}

		public bool SetNamespace(uint roleId, string @namespace)
		{
			return this.DataAccess.Update<IRole>(new
				{
					Namespace = string.IsNullOrWhiteSpace(@namespace) ? null : @namespace.Trim()
				}, new Condition(nameof(IRole.RoleId), roleId)) > 0;
		}

		public int SetNamespaces(string oldNamespace, string newNamespace)
		{
			return this.DataAccess.Update<IRole>(new
				{
					Namespace = string.IsNullOrWhiteSpace(newNamespace) ? null : newNamespace.Trim(),
				}, new Condition(nameof(IRole.Namespace), oldNamespace));
		}

		public bool SetName(uint roleId, string name)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new ArgumentNullException(nameof(name));

			//验证指定的名称是否合法
			this.OnValidateName(name);

			//确保角色名是审核通过的
			this.Censor(name);

			return this.DataAccess.Update<IRole>(new
			{
				Name = name.Trim()
			},
			new Condition(nameof(IRole.RoleId), roleId)) > 0;
		}

		public bool SetFullName(uint roleId, string fullName)
		{
			return this.DataAccess.Update<IRole>(new
			{
				FullName = string.IsNullOrWhiteSpace(fullName) ? null : fullName.Trim(),
			},
			new Condition(nameof(IRole.RoleId), roleId)) > 0;
		}

		public bool SetDescription(uint roleId, string description)
		{
			return this.DataAccess.Update<IRole>(new
			{
				Description = string.IsNullOrEmpty(description) ? null : description
			}, new Condition(nameof(IRole.RoleId), roleId)) > 0;
		}

		public int Delete(params uint[] ids)
		{
			if(ids == null || ids.Length < 1)
				return 0;

			int result = 0;

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				result = this.DataAccess.Delete<IRole>(Condition.In(nameof(IRole.RoleId), ids));

				if(result > 0)
				{
					this.DataAccess.Delete<Member>(Condition.Equal(nameof(Member.MemberType), MemberType.Role) & Condition.In(nameof(Member.MemberId), ids));
					this.DataAccess.Delete<Permission>(Condition.Equal(nameof(Permission.MemberType), MemberType.Role) & Condition.In(nameof(Permission.MemberId), ids));
					this.DataAccess.Delete<PermissionFilter>(Condition.Equal(nameof(PermissionFilter.MemberType), MemberType.Role) & Condition.In(nameof(PermissionFilter.MemberId), ids));
				}

				transaction.Commit();
			}

			return result;
		}

		public bool Create(IRole role)
		{
			if(role == null)
				throw new ArgumentNullException(nameof(role));

			return this.Create(new[] { role }) > 0;
		}

		public int Create(IEnumerable<IRole> roles)
		{
			if(roles == null)
				return 0;

			foreach(var role in roles)
			{
				if(role == null)
					continue;

				//如果未指定角色名，则为其设置一个随机名
				if(string.IsNullOrWhiteSpace(role.Name))
					role.Name = "R" + Randomizer.GenerateString();

				//如果当前用户的命名空间不为空，则新增角色的命名空间必须与当前用户一致
				if(!string.IsNullOrEmpty(this.Credential.User.Namespace))
					role.Namespace = this.Credential.User.Namespace;

				//验证指定的名称是否合法
				this.OnValidateName(role.Name);

				//确保角色名是审核通过的
				this.Censor(role.Name);

				//确认角色名是否存在
				if(this.Exists(role.Name, role.Namespace))
					throw new DataConflictException(Zongsoft.Resources.ResourceUtility.GetString("Text.RoleConflict"));

				//确保角色全称不为空
				if(string.IsNullOrEmpty(role.FullName))
					role.FullName = role.Name;
			}

			return this.DataAccess.InsertMany<IRole>(roles);
		}
		#endregion

		#region 成员管理
		public bool InRole(uint userId, uint roleId)
		{
			//获取指定用户编号对应的用户
			var user = this.DataAccess.Select<IUser>(Condition.Equal("UserId", userId), "!, UserId, Name, Namespace").FirstOrDefault();

			//如果指定的用户编号对应的是系统内置管理员（即 Administrator）则进行特殊处理，即系统内置管理员账号只能默认属于内置的管理员角色，它不能隶属于其它角色
			if(user != null && string.Equals(user.Name, MembershipHelper.Administrator, StringComparison.OrdinalIgnoreCase))
			{
				//获取指定角色编号对应的角色名
				var role = this.DataAccess.Select<IRole>(Condition.Equal("RoleId", roleId), "!, RoleId, Name, Namespace").FirstOrDefault();

				//如果指定的角色编号对应的是系统内置管理员角色（即 Administrators）则返回真，否则一律返回假。
				return role != null &&
				       string.Equals(role.Name, MembershipHelper.Administrators, StringComparison.OrdinalIgnoreCase) &&
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
			var user = this.DataAccess.Select<IUser>(Condition.Equal("UserId", userId), "!, UserId, Name, Namespace").FirstOrDefault();

			//如果指定的用户编号对应的是系统内置管理员（即 Administrator）则进行特殊处理，即系统内置管理员账号只能默认属于内置的管理员角色，它不能隶属于其它角色
			if(user != null && string.Equals(user.Name, MembershipHelper.Administrator, StringComparison.OrdinalIgnoreCase))
				return roleNames.Contains(MembershipHelper.Administrators, StringComparer.OrdinalIgnoreCase);

			//处理非系统内置管理员账号
			if(MembershipHelper.GetAncestors(this.DataAccess, userId, MemberType.User, out var flats, out var hierarchies) > 0)
				return flats.Any(role => roleNames.Contains(role.Name));

			return false;
		}

		public IEnumerable<IRole> GetRoles(uint memberId, MemberType memberType)
		{
			var members = this.DataAccess.Select<Member>(Condition.Equal("MemberId", memberId) & Condition.Equal("MemberType", memberType), "*, Role{*}");

			return members.Select(m => m.Role);
		}

		public IEnumerable<Member> GetMembers(uint roleId, string schema = null)
		{
			//查出指定角色的所有子级成员
			return this.DataAccess.Select<Member>(Condition.Equal("RoleId", roleId), schema);
		}

		public int SetMembers(uint roleId, params Member[] members)
		{
			return this.SetMembers(roleId, members, false);
		}

		public int SetMembers(uint roleId, IEnumerable<Member> members, bool shouldResetting = false)
		{
			if(members == null)
				return 0;

			//如果指定角色编号不存在则退出
			if(!this.DataAccess.Exists<IRole>(Condition.Equal(nameof(IRole.RoleId), roleId)))
				return -1;

			int count = 0;

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				//清空指定角色的所有成员
				if(shouldResetting)
					this.DataAccess.Delete<Member>(Condition.Equal(nameof(Member.RoleId), roleId));

				//插入指定的角色成员集到数据库中
				this.DataAccess.InsertMany<Member>(members.Select(m => new Member(roleId, m.MemberId, m.MemberType)));

				//提交事务
				transaction.Commit();
			}

			return count;
		}

		public int Delete(uint roleId)
		{
			return this.DataAccess.Delete<Member>(Condition.Equal(nameof(Member.RoleId), roleId));
		}

		public bool Delete(uint roleId, uint memberId, MemberType memberType)
		{
			return this.DataAccess.Delete<Member>(
				Condition.Equal(nameof(Member.RoleId), roleId) &
				Condition.Equal(nameof(Member.MemberId), memberId) &
				Condition.Equal(nameof(Member.MemberType), memberType)) > 0;
		}
		#endregion

		#region 虚拟方法
		protected virtual void OnValidateName(string name)
		{
			var validator = _services?.Resolve<IValidator<string>>("role.name");

			if(validator != null)
				validator.Validate(name, message => throw new SecurityException("rolename.illegality", message));
		}
		#endregion

		#region 私有方法
		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private void Censor(string name)
		{
			var censorship = this.Censorship;

			if(censorship != null && censorship.IsBlocked(name, Zongsoft.Security.Censorship.KEY_NAMES, Zongsoft.Security.Censorship.KEY_SENSITIVES))
				throw new CensorshipException(string.Format("Illegal '{0}' name of role.", name));
		}

		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private Condition GetNamespace(string @namespace)
		{
			if(string.IsNullOrEmpty(@namespace))
				return Condition.Equal(nameof(IRole.Namespace), this.Credential.User.Namespace);
			else if(@namespace != "*")
				return Condition.Equal(nameof(IRole.Namespace), @namespace);

			return null;
		}
		#endregion
	}
}
