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
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
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
		[ServiceDependency(IsRequired = true)]
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

		[ServiceDependency(IsRequired = true)]
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

		[ServiceDependency(IsRequired = true)]
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

		[ServiceDependency(IsRequired = true)]
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
		[Authorization]
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

		public virtual object Delete(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				return this.BadRequest();

			var count = this.RoleProvider.Delete(Common.StringExtension.Slice<uint>(id, chr => chr == ',' || chr == '|', uint.TryParse).Where(p => p > 0).ToArray());
			return count > 0 ? (IHttpActionResult)this.Ok(count) : this.NotFound();
		}

		public virtual object Post(IRole model)
		{
			if(model == null)
				return this.BadRequest();

			if(this.RoleProvider.Create(model))
				return model;

			return this.Conflict();
		}

		[HttpPatch]
		[ActionName("Namespace")]
		public async Task<IHttpActionResult> SetNamespace(uint id)
		{
			var content = await this.Request.Content.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			return this.RoleProvider.SetNamespace(id, content) ? (IHttpActionResult)this.Ok() : this.NotFound();
		}

		[HttpPatch]
		[ActionName("Name")]
		public async Task<IHttpActionResult> SetName(uint id)
		{
			var content = await this.Request.Content.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			return this.RoleProvider.SetName(id, content) ? (IHttpActionResult)this.Ok() : this.NotFound();
		}

		[HttpPatch]
		[ActionName("FullName")]
		public async Task<IHttpActionResult> SetFullName(uint id)
		{
			var content = await this.Request.Content.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			return this.RoleProvider.SetFullName(id, content) ? (IHttpActionResult)this.Ok() : this.NotFound();
		}

		[HttpPatch]
		[ActionName("Description")]
		public async Task<IHttpActionResult> SetDescription(uint id)
		{
			var content = await this.Request.Content.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			return this.RoleProvider.SetDescription(id, content) ? (IHttpActionResult)this.Ok() : this.NotFound();
		}

		[HttpGet]
		[Authorization(Suppressed = true)]
		public virtual IHttpActionResult Exists(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				return this.BadRequest();

			var existed = false;
			var userId = Utility.ResolvePattern(id, out var identity, out var @namespace, out var suffix);

			if(userId > 0)
				existed = this.RoleProvider.Exists(userId);
			else
				existed = this.RoleProvider.Exists(identity, @namespace);

			return existed ? (IHttpActionResult)this.Ok() : this.NotFound();
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
		public IHttpActionResult SetMember(uint id, string args)
		{
			if(string.IsNullOrEmpty(args))
				return this.BadRequest();

			var parts = args.Split(':');

			if(!Enum.TryParse<MemberType>(parts[0], true, out var memberType))
				return this.BadRequest("Invalid value of the member-type argument.");

			if(!uint.TryParse(parts[1], out var memberId))
				return this.BadRequest("Invalid value of the member-id argument.");

			return this.MemberProvider.SetMembers(id, new[] { new Member(id, memberId, memberType) }, false) > 0 ?
				(IHttpActionResult)this.Created(this.Request.RequestUri.Relative("."), 1) : this.StatusCode(System.Net.HttpStatusCode.NoContent);
		}

		[HttpPost]
		[ActionName("Members")]
		public IHttpActionResult SetMembers(uint id, [FromBody]IEnumerable<Member> members, [FromUri]bool reset = false)
		{
			var count = this.MemberProvider.SetMembers(id, members, reset);
			return count > 0 ? (IHttpActionResult)this.Created(this.Request.RequestUri, count) : this.StatusCode(System.Net.HttpStatusCode.NoContent);
		}

		[HttpDelete]
		[ActionName("Member")]
		public IHttpActionResult RemoveMember(uint id, string args)
		{
			if(string.IsNullOrEmpty(args))
				return this.BadRequest();

			var parts = args.Split(':');

			if(!Enum.TryParse<MemberType>(parts[0], true, out var memberType))
				return this.BadRequest("Invalid value of the member-type argument.");

			if(!uint.TryParse(parts[1], out var memberId))
				return this.BadRequest("Invalid value of the member-id argument.");

			return this.MemberProvider.RemoveMember(id, memberId, memberType) ?
				(IHttpActionResult)this.StatusCode(System.Net.HttpStatusCode.NoContent) : this.NotFound();
		}

		[HttpDelete]
		[ActionName("Members")]
		public IHttpActionResult RemoveMembers(uint id)
		{
			var count = this.MemberProvider.SetMembers(id, null);
			return count > 0 ? (IHttpActionResult)this.Ok(count) : this.StatusCode(System.Net.HttpStatusCode.NoContent);
		}
		#endregion

		#region 授权方法
		[HttpGet]
		public IEnumerable<AuthorizationToken> Authorizes(uint id)
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
		public IHttpActionResult SetPermissions(uint id, [FromRoute("args")]string schemaId, [FromBody]IEnumerable<Permission> permissions, [FromUri]bool reset = false)
		{
			var count = this.PermissionProvider.SetPermissions(id, MemberType.Role, schemaId, permissions, reset);
			return count > 0 ? (IHttpActionResult)this.Created(this.Request.RequestUri, count) : this.StatusCode(System.Net.HttpStatusCode.NoContent);
		}

		[HttpDelete]
		[ActionName("Permission")]
		public IHttpActionResult RemovePermission(uint id, [FromRoute("args")]string schemaId, [FromRoute("args")]string actionId)
		{
			if(string.IsNullOrEmpty(schemaId) || string.IsNullOrEmpty(actionId))
				return this.BadRequest();

			return this.PermissionProvider.RemovePermission(id, MemberType.Role, schemaId, actionId) ?
				(IHttpActionResult)this.StatusCode(System.Net.HttpStatusCode.NoContent) : this.NotFound();
		}

		[HttpDelete]
		[ActionName("Permissions")]
		public IHttpActionResult RemovePermissions(uint id, [FromRoute("args")]string schemaId = null)
		{
			var count = this.PermissionProvider.SetPermissions(id, MemberType.Role, schemaId, null, true);
			return count > 0 ? (IHttpActionResult)this.Ok(count) : this.NotFound();
		}

		[HttpGet]
		[ActionName("PermissionFilters")]
		public IEnumerable<PermissionFilter> GetPermissionFilters(uint id, [FromRoute("args")]string schemaId = null)
		{
			return this.PermissionProvider.GetPermissionFilters(id, MemberType.Role, schemaId);
		}

		[HttpPost]
		[ActionName("PermissionFilters")]
		public IHttpActionResult SetPermissionFilters(uint id, [FromRoute("args")]string schemaId, [FromBody]IEnumerable<PermissionFilter> permissions, [FromUri]bool reset = false)
		{
			var count = this.PermissionProvider.SetPermissionFilters(id, MemberType.Role, schemaId, permissions, reset);
			return count > 0 ? (IHttpActionResult)this.Created(this.Request.RequestUri, count) : this.StatusCode(System.Net.HttpStatusCode.NoContent);
		}

		[HttpDelete]
		[ActionName("PermissionFilter")]
		public IHttpActionResult RemovePermissionFilter(uint id, [FromRoute("args")]string schemaId, [FromRoute("args")]string actionId)
		{
			if(string.IsNullOrEmpty(schemaId) || string.IsNullOrEmpty(actionId))
				return this.BadRequest();

			return this.PermissionProvider.RemovePermissionFilter(id, MemberType.Role, schemaId, actionId) ?
				(IHttpActionResult)this.StatusCode(System.Net.HttpStatusCode.NoContent) : this.NotFound();
		}

		[HttpDelete]
		[ActionName("PermissionFilters")]
		public IHttpActionResult RemovePermissionFilters(uint id, [FromRoute("args")]string schemaId = null)
		{
			var count = this.PermissionProvider.SetPermissionFilters(id, MemberType.Role, schemaId, null, true);
			return count > 0 ? (IHttpActionResult)this.Ok(count) : this.NotFound();
		}
		#endregion
	}
}
