/*
 *   _____                                ______
 *  /_   /  ____  ____  ____  _________  / __/ /_
 *    / /  / __ \/ __ \/ __ \/ ___/ __ \/ /_/ __/
 *   / /__/ /_/ / / / / /_/ /\_ \/ /_/ / __/ /_
 *  /____/\____/_/ /_/\__  /____/\____/_/  \__/
 *                   /____/
 *
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@qq.com>
 *
 * Copyright (C) 2015-2019 Zongsoft Corporation <http://www.zongsoft.com>
 *
 * This file is part of Zongsoft.Security.Web.
 *
 * Zongsoft.Security.Web is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Zongsoft.Security.Web is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Zongsoft.Security.Web; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;

using Zongsoft.Data;
using Zongsoft.Services;
using Zongsoft.Web.Http;
using Zongsoft.Security.Membership;

namespace Zongsoft.Security.Web.Http.Controllers
{
	[Authorization(Roles = "Security")]
	public class RoleController : ApiController
	{
		#region 成员字段
		private IAuthorizer _authorizer;
		private IRoleProvider _roleProvider;
		private IMemberProvider _memberProvider;
		private IPermissionProvider _permissionProvider;
		#endregion

		#region 公共属性
		[ServiceDependency]
		public IAuthorizer Authorizer
		{
			get
			{
				return _authorizer;
			}
			set
			{
				_authorizer = value ?? throw new ArgumentNullException();
			}
		}

		[ServiceDependency]
		public IRoleProvider RoleProvider
		{
			get
			{
				return _roleProvider;
			}
			set
			{
				_roleProvider = value ?? throw new ArgumentNullException();
			}
		}

		[ServiceDependency]
		public IMemberProvider MemberProvider
		{
			get
			{
				return _memberProvider;
			}
			set
			{
				_memberProvider = value ?? throw new ArgumentNullException();
			}
		}

		[ServiceDependency]
		public IPermissionProvider PermissionProvider
		{
			get
			{
				return _permissionProvider;
			}
			set
			{
				_permissionProvider = value ?? throw new ArgumentNullException();
			}
		}
		#endregion

		#region 公共方法
		public virtual object Get(string id = null, [FromUri]Paging paging = null)
		{
			//如果标识为空或星号，则进行多角色查询
			if(string.IsNullOrEmpty(id) || id == "*")
				return this.RoleProvider.GetRoles(id, paging);

			//确认角色编号及标识
			var roleId = Utility.ResolvePattern(id, out var identity, out var @namespace, out var suffix);

			//如果ID参数是数字则以编号方式返回唯一的角色信息
			if(roleId > 0)
				return this.RoleProvider.GetRole(roleId);

			//如果角色标识为空或星号，则进行命名空间查询
			if(string.IsNullOrEmpty(identity) || identity == "*")
				return this.RoleProvider.GetRoles(@namespace, paging);

			//返回指定标识的角色信息
			return this.RoleProvider.GetRole(identity, @namespace);
		}

		public virtual int Delete(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				return 0;

			var parts = id.Split(',').Where(p => p.Length > 0).Select(p => uint.Parse(p)).Where(p => p > 0).ToArray();

			if(parts.Length > 0)
				return this.RoleProvider.Delete(parts);

			return 0;
		}

		public virtual object Post(IRole model)
		{
			if(model == null)
				throw new HttpResponseException(System.Net.HttpStatusCode.BadRequest);

			if(this.RoleProvider.Create(model))
				return model;

			throw new HttpResponseException(System.Net.HttpStatusCode.Conflict);
		}

		[HttpPatch]
		[ActionName("Namespace")]
		public void SetNamespace(uint id, string args)
		{
			if(string.IsNullOrWhiteSpace(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing namespace value of the role.");

			if(!this.RoleProvider.SetNamespace(id, args))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpPatch]
		[ActionName("Name")]
		public void SetName(uint id, string args)
		{
			if(string.IsNullOrWhiteSpace(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing name value of the role.");

			if(!this.RoleProvider.SetName(id, args))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpPatch]
		[ActionName("FullName")]
		public void SetFullName(uint id, string args)
		{
			if(string.IsNullOrWhiteSpace(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing full-name value of the role.");

			if(!this.RoleProvider.SetFullName(id, args))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpPatch]
		[ActionName("Description")]
		public void SetDescription(uint id, string args)
		{
			if(string.IsNullOrWhiteSpace(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing description value of the role.");

			if(!this.RoleProvider.SetDescription(id, args))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpGet]
		[Authorization(Suppressed = true)]
		public virtual void Exists(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				throw new HttpResponseException(System.Net.HttpStatusCode.BadRequest);

			var existed = false;
			var roleId = Utility.ResolvePattern(id, out var identity, out var @namespace, out var suffix);

			if(roleId > 0)
				existed = this.RoleProvider.Exists(roleId);
			else
				existed = this.RoleProvider.Exists(identity, @namespace);

			if(!existed)
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}
		#endregion

		#region 成员方法
		[HttpGet]
		[ActionName("Roles")]
		public IEnumerable<IRole> GetRoles(uint id)
		{
			return this.MemberProvider.GetRoles(id, MemberType.Role);
		}

		[HttpGet]
		[ActionName("Members")]
		public IEnumerable<Member> GetMembers(uint id)
		{
			return this.MemberProvider.GetMembers(id, this.Request.GetDataSchema());
		}

		[HttpPost]
		[ActionName("Member")]
		public void SetMember(uint id, string args)
		{
			if(string.IsNullOrEmpty(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing required member argument.");

			var parts = args.Split(':');

			if(!Enum.TryParse<MemberType>(parts[0], true, out var memberType))
				throw HttpResponseExceptionUtility.BadRequest("Invalid value of the member-type argument.");

			if(!uint.TryParse(parts[1], out var memberId))
				throw HttpResponseExceptionUtility.BadRequest("Invalid value of the member-id argument.");

			this.MemberProvider.SetMembers(id, new[] { new Member(id, memberId, memberType) }, false);
		}

		[HttpPost]
		[ActionName("Members")]
		public int SetMembers(uint id, [FromBody]IEnumerable<Member> members)
		{
			return this.MemberProvider.SetMembers(id, members, false);
		}

		[HttpDelete]
		[ActionName("Member")]
		public void RemoveMember(uint id, string args)
		{
			if(string.IsNullOrEmpty(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing required member argument.");

			var parts = args.Split(':');

			if(!Enum.TryParse<MemberType>(parts[0], true, out var memberType))
				throw HttpResponseExceptionUtility.BadRequest("Invalid value of the member-type argument.");

			if(!uint.TryParse(parts[1], out var memberId))
				throw HttpResponseExceptionUtility.BadRequest("Invalid value of the member-id argument.");

			if(!this.MemberProvider.Delete(id, memberId, memberType))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpDelete]
		[ActionName("Members")]
		public object RemoveMembers(uint id)
		{
			var count = this.MemberProvider.Delete(id);

			if(count > 0)
				return count;

			return new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.NoContent);
		}
		#endregion

		#region 授权方法
		[HttpGet]
		public IEnumerable<AuthorizationState> Authorizes(uint id)
		{
			return this.Authorizer.Authorizes(id, MemberType.Role);
		}
		#endregion

		#region 权限方法
		[HttpGet]
		[ActionName("Permissions")]
		public IEnumerable<Permission> GetPermissions(uint id, [FromRoute("args")]string schemaId = null)
		{
			return this.PermissionProvider.GetPermissions(id, MemberType.Role, schemaId);
		}

		[HttpPost]
		[ActionName("Permissions")]
		public void SetPermissions(uint id, [FromRoute("args")]string schemaId, [FromBody]IEnumerable<Permission> permissions)
		{
			this.PermissionProvider.SetPermissions(id, MemberType.Role, schemaId, permissions);
		}

		[HttpGet]
		[ActionName("PermissionFilters")]
		public IEnumerable<PermissionFilter> GetPermissionFilters(uint id, [FromRoute("args")]string schemaId = null)
		{
			return this.PermissionProvider.GetPermissionFilters(id, MemberType.Role, schemaId);
		}

		[HttpPost]
		[ActionName("PermissionFilters")]
		public void SetPermissionFilters(uint id, [FromRoute("args")]string schemaId, [FromBody]IEnumerable<PermissionFilter> permissions)
		{
			this.PermissionProvider.SetPermissionFilters(id, MemberType.Role, schemaId, permissions);
		}
		#endregion
	}
}
