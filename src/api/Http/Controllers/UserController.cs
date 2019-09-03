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
using Zongsoft.Security.Membership;
using Zongsoft.Web.Http;

namespace Zongsoft.Security.Web.Http.Controllers
{
	[Authorization(AuthorizationMode.Identity)]
	public class UserController : ApiController
	{
		#region 成员字段
		private IUserProvider _userProvider;
		private IAuthorizer _authorizer;
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
		public IUserProvider UserProvider
		{
			get
			{
				return _userProvider;
			}
			set
			{
				_userProvider = value ?? throw new ArgumentNullException();
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
		/// <summary>
		/// 查询指定编号或用户标识、命名空间的用户。
		/// </summary>
		/// <param name="id">指定的路由参数，如果该参数为纯数字则会被当做为用户编号；否则请参考备注部分的处理规则。</param>
		/// <param name="paging">指定的查询分页设置。</param>
		/// <returns>返回的用户或用户集。</returns>
		/// <remarks>
		///		<para>注意：由于路由匹配约定，对于首字符为字母并且中间字符为字母、数字、下划线的路由数据并不会被匹配为<paramref name="id"/>，
		///		因此对于查询用户标识和命名空间的组合条件，该参数应该使用冒号进行组合；而对于查询指定命名空间内的所有用户则应以冒号结尾，大致示意如下：</para>
		///		<list type="bullet">
		///			<listheader>
		///				<term>URL</term>
		///				<description>备注</description>
		///			</listheader>
		///			<item>
		///				<term>/api/Security/User/*</term>
		///				<description>查询系统中的所有用户，即忽略命名空间。</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User</term>
		///				<description>查询命名空间为空的所有用户。</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User/101</term>
		///				<description>查询用户<seealso cref="User.UserId"/>为101的用户。</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User/administrator</term>
		///				<description>查询用户<seealso cref="User.Name"/>为：Administrator，且<seealso cref="User.Namespace"/>为空的用户。</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User/13812345678!phone</term>
		///				<description>
		///					<para>因为手机号与用户编号都是数字，所以必须以叹号分隔的后缀以示区别。</para>
		///					<para>查询用户<seealso cref="User.Phone"/>为：13812345678，且<seealso cref="User.Namespace"/>为空的用户。</para>
		///				</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User/popeye@zongsoft.com</term>
		///				<description>查询用户<seealso cref="User.Email"/>为：popeye@zongsoft.com，且<seealso cref="User.Namespace"/>为空的用户。</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User/zongsoft:popeye</term>
		///				<description>查询用户<seealso cref="User.Name"/>为：Popeye，且<seealso cref="User.Namespace"/>为：zongsoft的用户。</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User/zongsoft:13812345678</term>
		///				<description>查询用户<seealso cref="User.Phone"/>为：13812345678，且<seealso cref="User.Namespace"/>为：zongsoft的用户。</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User/zongsoft:popeye@zongsoft.com</term>
		///				<description>查询用户<seealso cref="User.Email"/>为：popeye@zongsoft.com，且<seealso cref="User.Namespace"/>为：zongsoft的用户。</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User/zongsoft:*</term>
		///				<description>查询<seealso cref="User.Namespace"/>为：zongsoft的所有用户。</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User/:admin</term>
		///				<description>查询<seealso cref="User.Namespace"/>为空，且用户<seealso cref="User.Name"/>为：Admin 的用户。</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User/:13812345678</term>
		///				<description>查询<seealso cref="User.Namespace"/>为空，且用户<seealso cref="User.Phone"/>为：13812345678 的用户。</description>
		///			</item>
		///			<item>
		///				<term>/api/Security/User/:zongsoft@gmail.com</term>
		///				<description>查询<seealso cref="User.Namespace"/>为空，且用户<seealso cref="User.Email"/>为：zongsoft@gmail.com 的用户。</description>
		///			</item>
		///		</list>
		/// </remarks>
		public virtual object Get(string id = null, [FromUri]Paging paging = null)
		{
			//如果标识为空或星号，则进行多用户查询
			if(string.IsNullOrEmpty(id) || id == "*")
				return this.UserProvider.GetUsers(id, paging);

			//解析用户标识参数
			var userId = Utility.ResolvePattern(id, out var identity, out var @namespace, out var suffix);

			//如果ID参数是数字则以编号方式返回唯一的用户信息
			if(userId > 0)
				return this.UserProvider.GetUser(userId);

			//如果用户标识为空或星号，则进行命名空间查询
			if(string.IsNullOrEmpty(identity) || identity == "*")
				return this.UserProvider.GetUsers(@namespace, paging);

			//返回指定标识的用户信息
			return this.UserProvider.GetUser(identity, @namespace);
		}

		public virtual int Delete(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				return 0;

			var parts = id.Split(',', ';').Where(p => p.Length > 0).Select(p => uint.Parse(p)).Where(p => p > 0).ToArray();

			if(parts.Length > 0)
				return this.UserProvider.Delete(parts);

			return 0;
		}

		public virtual object Post(IUser model)
		{
			if(model == null)
				throw new HttpResponseException(System.Net.HttpStatusCode.BadRequest);

			string password = null;

			//从请求消息的头部获取指定的用户密码
			if(this.Request.Headers.TryGetValues("x-password", out var values) && values != null)
				password = values.FirstOrDefault();

			if(this.UserProvider.Create(model, password))
				return model;

			throw new HttpResponseException(System.Net.HttpStatusCode.Conflict);
		}

		[HttpPatch]
		[ActionName("Namespace")]
		public void SetNamespace(uint id, string args)
		{
			if(string.IsNullOrWhiteSpace(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing namespace value of the user.");

			if(!this.UserProvider.SetNamespace(id, args))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpPatch]
		[ActionName("Name")]
		public void SetName(uint id, string args)
		{
			if(string.IsNullOrWhiteSpace(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing name value of the user.");

			if(!this.UserProvider.SetName(id, args))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpPatch]
		[ActionName("FullName")]
		public void SetFullName(uint id, string args)
		{
			if(string.IsNullOrWhiteSpace(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing full-name value of the user.");

			if(!this.UserProvider.SetFullName(id, args))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpPatch]
		[ActionName("Email")]
		public void SetEmail(uint id, string args)
		{
			if(string.IsNullOrWhiteSpace(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing email value of the user.");

			if(!this.UserProvider.SetEmail(id, args))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpPatch]
		[ActionName("Phone")]
		public void SetPhone(uint id, string args)
		{
			if(string.IsNullOrWhiteSpace(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing phone number of the user.");

			if(!this.UserProvider.SetPhone(id, args))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpPatch]
		[ActionName("Status")]
		public virtual void SetStatus(uint id, string args)
		{
			if(string.IsNullOrWhiteSpace(args) || !Common.Convert.TryConvertValue<UserStatus>(args, out var status))
				throw HttpResponseExceptionUtility.BadRequest("Invalid status value of the user.");

			if(!this.UserProvider.SetStatus(id, status))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpPatch]
		[ActionName("Description")]
		public void SetDescription(uint id, string args)
		{
			if(string.IsNullOrWhiteSpace(args))
				throw HttpResponseExceptionUtility.BadRequest("Missing description value of the user.");

			if(!this.UserProvider.SetDescription(id, args))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpGet]
		[Authorization(AuthorizationMode.Anonymous)]
		public virtual void Exists(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				throw new HttpResponseException(System.Net.HttpStatusCode.BadRequest);

			var existed = false;
			var userId = Utility.ResolvePattern(id, out var identity, out var @namespace, out var suffix);

			if(userId > 0)
				existed = this.UserProvider.Exists(userId);
			else
				existed = this.UserProvider.Exists(identity, @namespace);

			if(!existed)
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpGet]
		[Authorization(AuthorizationMode.Anonymous)]
		public void Verify(uint id, [FromRoute("args")]string type, [FromUri]string secret)
		{
			if(!this.UserProvider.Verify(id, type, secret))
				throw new HttpResponseException(System.Net.HttpStatusCode.BadRequest);
		}
		#endregion

		#region 密码处理
		[HttpGet]
		public void HasPassword(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				throw HttpResponseExceptionUtility.BadRequest("Missing required argument.");

			var existed = false;
			var userId = Utility.ResolvePattern(id, out var identity, out var @namespace, out var suffix);

			if(userId > 0)
				existed = this.UserProvider.HasPassword(userId);
			else
				existed = this.UserProvider.HasPassword(identity, @namespace);

			if(!existed)
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpPut]
		public void ChangePassword(uint id, PasswordChangeEntity password)
		{
			if(!this.UserProvider.ChangePassword(id, password.OldPassword, password.NewPassword))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}

		[HttpPost]
		[Authorization(AuthorizationMode.Anonymous)]
		public uint ForgetPassword(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				throw HttpResponseExceptionUtility.BadRequest("Missing required argument.");

			var parts = id.Split(':');
			var userId = 0u;

			if(parts.Length > 1)
				userId = this.UserProvider.ForgetPassword(parts[1], parts[0]);
			else
				userId = this.UserProvider.ForgetPassword(parts[0], null);

			if(userId == 0)
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);

			return userId;
		}

		[HttpPost]
		[Authorization(AuthorizationMode.Anonymous)]
		public void ResetPassword(string id, [FromBody]PasswordResetEntity content)
		{
			if(!string.IsNullOrWhiteSpace(content.Secret))
			{
				if(!uint.TryParse(id, out var userId))
					throw HttpResponseExceptionUtility.BadRequest("Invalid id argument, it must be a integer.");

				if(!this.UserProvider.ResetPassword(userId, content.Secret, content.Password))
					throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
			}
			else if(content.PasswordAnswers != null && content.PasswordAnswers.Length > 0)
			{
				var userId = Utility.ResolvePattern(id, out var identity, out var @namespace, out var suffix);

				//注意：该方法会将传入的纯数字的标识当做手机号处理
				if(userId > 0)
					identity = userId.ToString();

				if(!this.UserProvider.ResetPassword(identity, @namespace, content.PasswordAnswers, content.Password))
					throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
			}
			else
			{
				throw HttpResponseExceptionUtility.BadRequest();
			}
		}

		[HttpGet]
		[ActionName("PasswordQuestions")]
		[Authorization(AuthorizationMode.Anonymous)]
		public string[] GetPasswordQuestions(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				throw HttpResponseExceptionUtility.BadRequest("Missing required argument.");

			var userId = Utility.ResolvePattern(id, out var identity, out var @namespace, out var suffix);
			string[] result = null;

			if(userId > 0)
				result = this.UserProvider.GetPasswordQuestions(userId);
			else
				result = this.UserProvider.GetPasswordQuestions(identity, @namespace);

			//如果返回的结果为空表示指定的表示的用户不存在
			if(result == null)
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);

			//如果问题数组内容不是全空，则返回该数组
			for(int i = 0; i < result.Length; i++)
			{
				if(!string.IsNullOrEmpty(result[i]))
					return result;
			}

			//返回空
			return null;
		}

		[HttpPut]
		[ActionName("PasswordAnswers")]
		public void SetPasswordQuestionsAndAnswers(uint id, [FromBody]PasswordQuestionsAndAnswersEntity content)
		{
			if(!this.UserProvider.SetPasswordQuestionsAndAnswers(id, content.Password, content.Questions, content.Answers))
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}
		#endregion

		#region 成员方法
		[HttpGet]
		[ActionName("Roles")]
		public IEnumerable<IRole> GetRoles(uint id)
		{
			return this.MemberProvider.GetRoles(id, MemberType.User);
		}

		[HttpGet]
		[ActionName("In")]
		public void InRole([FromRoute("id")]uint userId, [FromRoute("args")]string roles)
		{
			if(string.IsNullOrEmpty(roles))
				throw new HttpResponseException(System.Net.HttpStatusCode.BadRequest);

			var result = false;

			if(uint.TryParse(roles, out var roleId))
				result = this.MemberProvider.InRole(userId, roleId);
			else
				result = this.MemberProvider.InRoles(userId, roles.Split(',', ';', '|').Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).ToArray());

			if(!result)
				throw new HttpResponseException(System.Net.HttpStatusCode.NotFound);
		}
		#endregion

		#region 授权方法
		[HttpGet]
		public void Authorize([FromRoute("id")]uint userId, [FromRoute("args")]string schemaId, [FromRoute("args")]string actionId)
		{
			if(string.IsNullOrWhiteSpace(schemaId))
				throw HttpResponseExceptionUtility.BadRequest("Missing schema for the authorize operation.");

			if(string.IsNullOrWhiteSpace(actionId))
				throw HttpResponseExceptionUtility.BadRequest("Missing action for the authorize operation.");

			if(!this.Authorizer.Authorize(userId, schemaId, actionId))
				throw new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
		}

		[HttpGet]
		public IEnumerable<AuthorizationState> Authorizes(uint id)
		{
			return this.Authorizer.Authorizes(id, MemberType.User);
		}
		#endregion

		#region 权限方法
		[HttpGet]
		[ActionName("Permissions")]
		public IEnumerable<Permission> GetPermissions(uint id, [FromRoute("args")]string schemaId = null)
		{
			return this.PermissionProvider.GetPermissions(id, MemberType.User, schemaId);
		}

		[HttpPost]
		[ActionName("Permissions")]
		public void SetPermissions(uint id, [FromRoute("args")]string schemaId, [FromBody]IEnumerable<Permission> permissions)
		{
			this.PermissionProvider.SetPermissions(id, MemberType.User, schemaId, permissions);
		}

		[HttpGet]
		[ActionName("PermissionFilters")]
		public IEnumerable<PermissionFilter> GetPermissionFilters(uint id, [FromRoute("args")]string schemaId = null)
		{
			return this.PermissionProvider.GetPermissionFilters(id, MemberType.User, schemaId);
		}

		[HttpPost]
		[ActionName("PermissionFilters")]
		public void SetPermissionFilters(uint id, [FromRoute("args")]string schemaId, [FromBody]IEnumerable<PermissionFilter> permissions)
		{
			this.PermissionProvider.SetPermissionFilters(id, MemberType.User, schemaId, permissions);
		}
		#endregion

		#region 内部结构
		public struct PasswordChangeEntity
		{
			public string OldPassword;
			public string NewPassword;
		}

		public struct PasswordResetEntity
		{
			public string Secret;
			public string Password;
			public string[] PasswordAnswers;
		}

		public struct PasswordQuestionsAndAnswersEntity
		{
			public string Password;
			public string[] Questions;
			public string[] Answers;
		}
		#endregion
	}
}
