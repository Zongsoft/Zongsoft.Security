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

using Zongsoft.Data;
using Zongsoft.Services;

namespace Zongsoft.Security.Membership
{
	public class Authentication : MarshalByRefObject, IAuthentication
	{
		#region 成员字段
		private IDataAccess _dataAccess;
		#endregion

		#region 事件声明
		public event EventHandler<AuthenticatedEventArgs> Authenticated;
		#endregion

		#region 构造函数
		public Authentication()
		{
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
				if(value == null)
					throw new ArgumentNullException();

				_dataAccess = value;
			}
		}
		#endregion

		#region 验证方法
		public AuthenticationResult Authenticate(string identity, string password, string @namespace = null)
		{
			if(string.IsNullOrWhiteSpace(identity))
				throw new ArgumentNullException("identity");

			byte[] storedPassword;
			byte[] storedPasswordSalt;
			UserStatus status;
			DateTime? statusTimestamp;

			//获取当前用户的密码及密码向量
			var userId = this.GetPassword(identity, @namespace, out storedPassword, out storedPasswordSalt, out status, out statusTimestamp);

			//如果帐户不存在，则抛出异常
			if(userId == null)
			{
				//激发“Authenticated”事件
				this.OnAuthenticated(new AuthenticatedEventArgs(identity, @namespace, false));

				//指定的用户名如果不存在则抛出验证异常
				throw new AuthenticationException(AuthenticationReason.InvalidIdentity);
			}

			//如果帐户尚未审核批准，则抛出异常
			if(status == UserStatus.Unapproved)
			{
				//激发“Authenticated”事件
				this.OnAuthenticated(new AuthenticatedEventArgs(identity, @namespace, false));

				//因为账户状态异常而抛出验证异常
				throw new AuthenticationException(AuthenticationReason.AccountUnapproved);
			}

			//如果帐户被暂停，则抛出异常
			if(status == UserStatus.Suspended)
			{
				//激发“Authenticated”事件
				this.OnAuthenticated(new AuthenticatedEventArgs(identity, @namespace, false));

				//因为账户状态异常而抛出验证异常
				throw new AuthenticationException(AuthenticationReason.AccountSuspended);
			}

			//如果帐户已经禁用(停用)，则抛出异常
			if(status == UserStatus.Disabled)
			{
				//激发“Authenticated”事件
				this.OnAuthenticated(new AuthenticatedEventArgs(identity, @namespace, false));

				//因为账户状态异常而抛出验证异常
				throw new AuthenticationException(AuthenticationReason.AccountDisabled);
			}

			//如果验证失败，则抛出异常
			if(!PasswordUtility.VerifyPassword(password, storedPassword, storedPasswordSalt, "SHA1"))
			{
				//激发“Authenticated”事件
				this.OnAuthenticated(new AuthenticatedEventArgs(identity, @namespace, false));

				//密码校验失败则抛出验证异常
				throw new AuthenticationException(AuthenticationReason.InvalidPassword);
			}

			//获取指定用户编号对应的用户对象
			var user = MembershipHelper.GetUser(this.DataAccess, userId.Value);

			//创建“Authenticated”事件参数
			var eventArgs = new AuthenticatedEventArgs(identity, @namespace, true, user);

			//激发“Authenticated”事件
			this.OnAuthenticated(eventArgs);

			//返回成功的验证结果
			return new AuthenticationResult(eventArgs.User ?? user, (eventArgs.HasExtendedProperties ? eventArgs.ExtendedProperties : null));
		}
		#endregion

		#region 虚拟方法
		protected virtual uint? GetPassword(string identity, string @namespace, out byte[] password, out byte[] passwordSalt, out UserStatus status, out DateTime? statusTimestamp)
		{
			if(string.IsNullOrWhiteSpace(identity))
				throw new ArgumentNullException("identity");

			return MembershipHelper.GetPassword(this.DataAccess, identity, @namespace, out password, out passwordSalt, out status, out statusTimestamp);
		}
		#endregion

		#region 激发事件
		protected virtual void OnAuthenticated(AuthenticatedEventArgs args)
		{
			var handler = this.Authenticated;

			if(handler != null)
				handler(this, args);
		}
		#endregion
	}
}
