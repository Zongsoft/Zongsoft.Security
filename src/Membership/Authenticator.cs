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
using System.Linq;
using System.Collections.Generic;

using Zongsoft.Data;
using Zongsoft.Services;

namespace Zongsoft.Security.Membership
{
	public class Authenticator : IAuthenticator
	{
		#region 成员字段
		private IDataAccess _dataAccess;
		private Attempter _attempter;
		#endregion

		#region 事件声明
		public event EventHandler<AuthenticatedEventArgs> Authenticated;
		#endregion

		#region 构造函数
		public Authenticator()
		{
		}
		#endregion

		#region 公共属性
		public string Name
		{
			get => "Normal";
		}

		[ServiceDependency]
		public Attempter Attempter
		{
			get
			{
				return _attempter;
			}
			set
			{
				_attempter = value;
			}
		}

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
		#endregion

		#region 验证方法
		public AuthenticationResult Authenticate(string identity, string password, string @namespace, string scene, IDictionary<string, object> parameters = null)
		{
			if(string.IsNullOrWhiteSpace(identity))
				throw new ArgumentNullException(nameof(identity));

			//获取当前用户的密码及密码向量
			var userId = this.GetPassword(identity, @namespace, out var storedPassword, out var storedPasswordSalt, out var status, out var statusTimestamp);

			//如果帐户不存在，则抛出异常
			if(userId == 0)
			{
				//激发“Authenticated”事件
				this.OnAuthenticated(new AuthenticatedEventArgs(identity, @namespace, scene));

				//指定的用户名如果不存在则抛出验证异常
				throw new AuthenticationException(AuthenticationReason.InvalidIdentity);
			}

			//获取验证失败的解决器
			var attempter = this.Attempter;

			//确认验证失败是否超出限制数，如果超出则抛出账号被禁用的异常
			if(attempter != null && !attempter.Verify(userId))
				throw new AuthenticationException(AuthenticationReason.AccountSuspended);

			switch(status)
			{
				case UserStatus.Unapproved:
					//激发“Authenticated”事件
					this.OnAuthenticated(new AuthenticatedEventArgs(identity, @namespace, scene));

					//因为账户状态异常而抛出验证异常
					throw new AuthenticationException(AuthenticationReason.AccountUnapproved);
				case UserStatus.Disabled:
					//激发“Authenticated”事件
					this.OnAuthenticated(new AuthenticatedEventArgs(identity, @namespace, scene));

					//因为账户状态异常而抛出验证异常
					throw new AuthenticationException(AuthenticationReason.AccountDisabled);
			}

			//如果验证失败，则抛出异常
			if(!PasswordUtility.VerifyPassword(password, storedPassword, storedPasswordSalt, "SHA1"))
			{
				//通知验证尝试失败
				if(attempter != null)
					attempter.Fail(userId);

				//激发“Authenticated”事件
				this.OnAuthenticated(new AuthenticatedEventArgs(identity, @namespace, scene));

				//密码校验失败则抛出验证异常
				throw new AuthenticationException(AuthenticationReason.InvalidPassword);
			}

			//通知验证尝试成功，即清空验证失败记录
			if(attempter != null)
				attempter.Done(userId);

			//获取指定用户编号对应的用户对象
			var user = this.DataAccess.Select<IUser>(Condition.Equal(nameof(IUser.UserId), userId)).FirstOrDefault();

			//创建“Authenticated”事件参数
			var eventArgs = new AuthenticatedEventArgs(identity, @namespace, user, scene, parameters);

			//激发“Authenticated”事件
			this.OnAuthenticated(eventArgs);

			//返回成功的验证结果
			return new AuthenticationResult(eventArgs.User ?? user, scene, (eventArgs.HasParameters ? eventArgs.Parameters : null));
		}
		#endregion

		#region 虚拟方法
		protected virtual uint GetPassword(string identity, string @namespace, out byte[] password, out long passwordSalt, out UserStatus status, out DateTime? statusTimestamp)
		{
			if(string.IsNullOrWhiteSpace(@namespace))
				@namespace = null;

			var entity = this.DataAccess.Select<UserSecret>(MembershipHelper.GetUserIdentity(identity) & Condition.Equal(nameof(IUser.Namespace), @namespace)).FirstOrDefault();

			if(entity.UserId == 0)
			{
				password = null;
				passwordSalt = 0;
				status = UserStatus.Active;
				statusTimestamp = null;
			}
			else
			{
				password = entity.Password;
				passwordSalt = entity.PasswordSalt;
				status = entity.Status;
				statusTimestamp = entity.StatusTimestamp;
			}

			return entity.UserId;
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

		[Zongsoft.Data.Entity("Security.User")]
		private struct UserSecret
		{
			public uint UserId;
			public byte[] Password;
			public long PasswordSalt;
			public UserStatus Status;
			public DateTime? StatusTimestamp;
		}
	}
}
