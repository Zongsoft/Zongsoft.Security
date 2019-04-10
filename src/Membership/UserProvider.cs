﻿/*
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
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Zongsoft.Data;
using Zongsoft.Common;
using Zongsoft.Services;

namespace Zongsoft.Security.Membership
{
	public class UserProvider : IUserProvider
	{
		#region 常量定义
		private const string KEY_EMAIL_SECRET = "user.email";
		private const string KEY_PHONE_SECRET = "user.phone";
		private const string KEY_FORGET_SECRET = "user.forget";
		#endregion

		#region 成员字段
		private IDataAccess _dataAccess;
		private Attempter _attempter;
		private ICensorship _censorship;
		private ISecretProvider _secretProvider;
		private Services.IServiceProvider _services;
		#endregion

		#region 构造函数
		public UserProvider(Services.IServiceProvider serviceProvider)
		{
			_services = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
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
		public Options.IConfiguration Configuration
		{
			get; set;
		}

		[ServiceDependency]
		public ISecretProvider SecretProvider
		{
			get
			{
				return _secretProvider;
			}
			set
			{
				_secretProvider = value;
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
		#endregion

		#region 用户管理
		public IUser GetUser(uint userId)
		{
			return this.DataAccess.Select<IUser>(Condition.Equal(nameof(IUser.UserId), GetUserId(userId))).FirstOrDefault();
		}

		public IUser GetUser(string identity, string @namespace)
		{
			return this.DataAccess.Select<IUser>(MembershipHelper.GetUserIdentityCondition(identity, @namespace)).FirstOrDefault();
		}

		public IEnumerable<IUser> GetUsers(string @namespace, Paging paging = null)
		{
			return this.DataAccess.Select<IUser>(MembershipHelper.GetNamespaceCondition(@namespace), paging);
		}

		public bool Exists(uint userId)
		{
			return this.DataAccess.Exists<IUser>(Condition.Equal(nameof(IUser.UserId), userId));
		}

		public bool Exists(string identity, string @namespace)
		{
			if(string.IsNullOrWhiteSpace(identity))
				return false;

			return this.DataAccess.Exists<IUser>(MembershipHelper.GetUserIdentityCondition(identity, @namespace));
		}

		public bool SetEmail(uint userId, string email)
		{
			//确认指定的用户编号是否有效
			userId = GetUserId(userId);

			//判断是否邮箱地址是否需要校验
			if(this.IsVerifyEmailRequired())
			{
				//获取指定编号的用户
				var user = this.GetUser(userId);

				if(user == null)
					return false;

				//发送邮箱地址更改的校验通知
				this.OnChangeEmail(user, email);

				//返回成功
				return true;
			}

			return this.DataAccess.Update<IUser>(
				new
				{
					Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
					Modification = DateTime.Now,
				}, Condition.Equal(nameof(IUser.UserId), userId)) > 0;
		}

		public bool SetPhoneNumber(uint userId, string phoneNumber)
		{
			//确认指定的用户编号是否有效
			userId = GetUserId(userId);

			//判断是否电话号码是否需要校验
			if(this.IsVerifyPhoneRequired())
			{
				//获取指定编号的用户
				var user = this.GetUser(userId);

				if(user == null)
					return false;

				//发送电话号码更改的校验通知
				this.OnChangePhone(user, phoneNumber);

				//返回成功
				return true;
			}

			return this.DataAccess.Update<IUser>(
				new
				{
					PhoneNumber = string.IsNullOrWhiteSpace(phoneNumber) ? null : phoneNumber.Trim(),
					Modification = DateTime.Now,
				}, Condition.Equal(nameof(IUser.UserId), userId)) > 0;
		}

		public bool SetNamespace(uint userId, string @namespace)
		{
			//确认指定的用户编号是否有效
			userId = GetUserId(userId);

			return this.DataAccess.Update<IUser>(
				new
				{
					Namespace = string.IsNullOrWhiteSpace(@namespace) ? null : @namespace.Trim(),
					Modification = DateTime.Now,
				},
				new Condition(nameof(IUser.UserId), userId)) > 0;
		}

		public int SetNamespaces(string oldNamespace, string newNamespace)
		{
			return this.DataAccess.Update<IUser>(
				new
				{
					Namespace = string.IsNullOrWhiteSpace(newNamespace) ? null : newNamespace.Trim(),
					Modification = DateTime.Now,
				},
				new Condition(nameof(IUser.Namespace), oldNamespace));
		}

		public bool SetName(uint userId, string name)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new ArgumentNullException(nameof(name));

			//确认指定的用户编号是否有效
			userId = GetUserId(userId);

			//验证指定的名称是否合法
			this.OnValidateName(name);

			//确保用户名是审核通过的
			this.Censor(name);

			return this.DataAccess.Update<IUser>(
				new
				{
					Name = name.Trim(),
					Modification = DateTime.Now,
				},
				new Condition(nameof(IUser.UserId), userId)) > 0;
		}

		public bool SetFullName(uint userId, string fullName)
		{
			//确认指定的用户编号是否有效
			userId = GetUserId(userId);

			return this.DataAccess.Update<IUser>(
				new
				{
					FullName = string.IsNullOrWhiteSpace(fullName) ? null : fullName.Trim(),
					Modification = DateTime.Now,
				},
				new Condition(nameof(IUser.UserId), userId)) > 0;
		}

		public bool SetStatus(uint userId, UserStatus status)
		{
			//确认指定的用户编号是否有效
			userId = GetUserId(userId);

			var timestamp = DateTime.Now;

			return this.DataAccess.Update<IUser>(
				new
				{
					Status = status,
					StatusTimestamp = timestamp,
					Modification = timestamp,
				},
				new Condition(nameof(IUser.UserId), userId)) > 0;
		}

		public bool SetDescription(uint userId, string description)
		{
			//确认指定的用户编号是否有效
			userId = GetUserId(userId);

			return this.DataAccess.Update<IUser>(
				new
				{
					Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
					Modification = DateTime.Now,
				},
				new Condition(nameof(IUser.UserId), userId)) > 0;
		}

		public int Delete(params uint[] ids)
		{
			if(ids == null || ids.Length < 1)
				return 0;

			int result = 0;

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				result = this.DataAccess.Delete<IUser>(Condition.In(nameof(IUser.UserId), ids));

				if(result > 0)
				{
					this.DataAccess.Delete<Member>(Condition.Equal(nameof(Member.MemberType), MemberType.User) & Condition.In(nameof(Member.MemberId), ids));
					this.DataAccess.Delete<Permission>(Condition.Equal(nameof(Permission.MemberType), MemberType.User) & Condition.In(nameof(Permission.MemberId), ids));
					this.DataAccess.Delete<PermissionFilter>(Condition.Equal(nameof(PermissionFilter.MemberType), MemberType.User) & Condition.In(nameof(PermissionFilter.MemberId), ids));
				}

				transaction.Commit();
			}

			return result;
		}

		public bool Create(IUser user, string password)
		{
			if(user == null)
				throw new ArgumentNullException("user");

			if(string.IsNullOrWhiteSpace(user.Name))
				throw new ArgumentException("The user name is empty.");

			//验证指定的名称是否合法
			this.OnValidateName(user.Name);

			//确认新密码是否符合密码规则
			this.OnValidatePassword(password);

			//确保用户名是审核通过的
			this.Censor(user.Name);

			//定义新用户要设置的邮箱地址和手机号码
			string email = null, phone = null;

			//如果新用户的“邮箱地址”不为空并且需要确认校验，则将新用户的“邮箱地址”设为空
			if(!string.IsNullOrWhiteSpace(user.Email) && this.IsVerifyEmailRequired())
			{
				email = user.Email;
				user.Email = null;
			}

			//如果新用户的“电话号码”不为空并且需要确认校验，则将新用户的“电话号码”设为空
			if(!string.IsNullOrWhiteSpace(user.PhoneNumber) && this.IsVerifyPhoneRequired())
			{
				phone = user.PhoneNumber;
				user.PhoneNumber = null;
			}

			//更新创建时间
			user.Creation = DateTime.Now;
			user.Modification = null;

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				if(this.DataAccess.Insert(user) < 1)
					return false;

				//有效的密码不能为空或全空格字符串
				if(!string.IsNullOrWhiteSpace(password))
				{
					//生成密码随机数
					var passwordSalt = this.GetPasswordSalt();

					this.DataAccess.Update<IUser>(new
					{
						Password = PasswordUtility.HashPassword(password, passwordSalt),
						PasswordSalt = passwordSalt,
					}, new Condition(nameof(IUser.UserId), user.UserId));
				}

				//发送邮箱地址确认校验通知
				if(!string.IsNullOrEmpty(email))
					this.OnChangeEmail(user, email);

				//发送电话号码确认校验通知
				if(!string.IsNullOrEmpty(phone))
					this.OnChangePhone(user, phone);

				//提交事务
				transaction.Commit();
			}

			return true;
		}

		public int Create(IEnumerable<IUser> users)
		{
			if(users == null)
				return 0;

			foreach(var user in users)
			{
				if(user == null)
					continue;

				if(string.IsNullOrWhiteSpace(user.Name))
					throw new ArgumentException("The user name is empty.");

				//验证指定的名称是否合法
				this.OnValidateName(user.Name);

				//确保用户名是审核通过的
				this.Censor(user.Name);

				//更新创建时间
				user.Creation = DateTime.Now;
				user.Modification = null;
			}

			return this.DataAccess.InsertMany(users);
		}
		#endregion

		#region 密码管理
		public bool HasPassword(uint userId)
		{
			return this.DataAccess.Exists<IUser>(Condition.Equal(nameof(IUser.UserId), GetUserId(userId)) & Condition.NotEqual("Password", null));
		}

		public bool HasPassword(string identity, string @namespace)
		{
			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			return this.DataAccess.Exists<IUser>(ConditionCollection.And(condition, Condition.NotEqual("Password", null)));
		}

		public bool ChangePassword(uint userId, string oldPassword, string newPassword)
		{
			//确认指定的用户编号是否有效
			userId = GetUserId(userId);

			//确认新密码是否符合密码规则
			this.OnValidatePassword(newPassword);

			//获取验证失败的解决器
			var attempter = this.Attempter;

			//确认验证失败是否超出限制数，如果超出则抛出账号被禁用的异常
			if(attempter != null && !attempter.Verify(userId))
				throw new AuthenticationException(AuthenticationReason.AccountSuspended);

			//获取用户密码及密码盐
			var secret = this.DataAccess.Select<UserPasswordToken>(Condition.Equal(nameof(IUser.UserId), userId)).FirstOrDefault();

			if(secret.UserId == 0)
				return false;

			if(!PasswordUtility.VerifyPassword(oldPassword, secret.Password, secret.PasswordSalt))
			{
				//通知验证尝试失败
				if(attempter != null)
					attempter.Fail(userId);

				//抛出验证失败异常
				throw new AuthenticationException(AuthenticationReason.InvalidPassword);
			}

			//通知验证尝试成功，即清空验证失败记录
			if(attempter != null)
				attempter.Done(userId);

			//重新生成密码随机数
			var passwordSalt = this.GetPasswordSalt();

			return this.DataAccess.Update<IUser>(
				new
				{
					Password = PasswordUtility.HashPassword(newPassword, passwordSalt),
					PasswordSalt = passwordSalt,
				}, Condition.Equal(nameof(IUser.UserId), userId)) > 0;
		}

		public uint ForgetPassword(string identity, string @namespace)
		{
			if(string.IsNullOrEmpty(identity))
				throw new ArgumentNullException(nameof(identity));

			var secretor = this.SecretProvider;

			if(secretor == null)
				throw new InvalidOperationException("Missing secret provider.");

			//解析用户标识的查询条件
			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace, out var identityType);

			//如果查询条件解析失败或用户标识为用户名，则抛出不支持的异常
			if(condition == null || identityType == UserIdentityType.Name)
				throw new NotSupportedException("Invalid user identity for the forget password operation.");

			//获取指定标识的用户信息
			var user = this.DataAccess.Select<IUser>(condition).FirstOrDefault();

			if(user == null)
				return 0;

			string secret = null;
			object parameter = null;

			switch(identityType)
			{
				case UserIdentityType.Email:
					//如果用户的邮箱地址为空，即无法通过邮箱寻回
					if(string.IsNullOrWhiteSpace(user.Email))
						throw new InvalidOperationException("The user's email is unset.");

					//生成校验密文
					secret = secretor.Generate($"{KEY_FORGET_SECRET}:{user.UserId}");

					//构造发送的邮件模板的参数
					parameter = new Dictionary<string, object>
					{
						{ "Secret", secret },
						{ "Data", user },
					};

					//发送忘记密码的邮件通知
					CommandExecutor.Default.Execute($"email.send -template:{KEY_FORGET_SECRET} {user.Email}", parameter);

					break;
				case UserIdentityType.PhoneNumber:
					//如果用户的电话号码为空，即无法通过短信寻回
					if(string.IsNullOrWhiteSpace(user.PhoneNumber))
						throw new InvalidOperationException("The user's phone-number is unset.");

					//生成校验密文
					secret = secretor.Generate($"{KEY_FORGET_SECRET}:{user.UserId}");

					//构造发送的短信模板的参数
					parameter = new Dictionary<string, object>
					{
						{ "Secret", secret },
						{ "Data", user },
					};

					//发送忘记密码的短信通知
					CommandExecutor.Default.Execute($"sms.send -template:{KEY_FORGET_SECRET} {user.PhoneNumber}", parameter);

					break;
				default:
					throw new SecurityException("Invalid user identity for the forget password operation.");
			}

			//返回执行成功的用户编号
			return user.UserId;
		}

		public bool ResetPassword(uint userId, string secret, string newPassword = null)
		{
			if(string.IsNullOrEmpty(secret))
				return false;

			var secretProvider = this.SecretProvider;

			if(secret == null)
				throw new InvalidOperationException("Missing secret provider.");

			//确认指定的用户编号是否有效
			userId = GetUserId(userId);

			//如果重置密码的校验码验证成功
			if(secretProvider.Verify($"{KEY_FORGET_SECRET}:{userId}", secret))
			{
				//确认新密码是否符合密码规则
				this.OnValidatePassword(newPassword);

				//定义要设置的用户密码结构
				var data = new UserPasswordToken(userId, null, 0);

				if(!string.IsNullOrWhiteSpace(newPassword))
				{
					//重新生成密码随机数
					var passwordSalt = this.GetPasswordSalt();

					//创建用户密码结构
					data = new UserPasswordToken(userId, PasswordUtility.HashPassword(newPassword, passwordSalt), passwordSalt);
				}

				//提交修改密码的更新操作
				return this.DataAccess.Update<IUser>(data, Condition.Equal(nameof(IUser.UserId), userId)) > 0;
			}

			//重置密码校验失败，抛出异常
			throw new SecurityException("verify.fail", "The secret verify fail for the operation.");
		}

		public bool ResetPassword(string identity, string @namespace, string[] passwordAnswers, string newPassword)
		{
			if(string.IsNullOrWhiteSpace(identity))
				throw new ArgumentNullException(nameof(identity));

			if(passwordAnswers == null || passwordAnswers.Length < 3)
				throw new ArgumentNullException(nameof(passwordAnswers));

			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			var record = this.DataAccess.Select<UserSecretAnswer>(condition).FirstOrDefault();

			if(record.UserId == 0)
				return false;

			//如果指定的用户没有设置密码问答，则抛出安全异常
			if((record.PasswordAnswer1 == null || record.PasswordAnswer1.Length == 0) &&
			   (record.PasswordAnswer2 == null || record.PasswordAnswer2.Length == 0) &&
			   (record.PasswordAnswer3 == null || record.PasswordAnswer3.Length == 0))
			{
				throw new SecurityException("Can not reset password, because the specified user's password questions and answers is unset.");
			}

			//如果密码问答的答案验证失败，则抛出安全异常
			if(!PasswordUtility.VerifyPassword(passwordAnswers[0], record.PasswordAnswer1, this.GetPasswordAnswerSalt(record.UserId, 1)) ||
			   !PasswordUtility.VerifyPassword(passwordAnswers[1], record.PasswordAnswer2, this.GetPasswordAnswerSalt(record.UserId, 2)) ||
			   !PasswordUtility.VerifyPassword(passwordAnswers[2], record.PasswordAnswer3, this.GetPasswordAnswerSalt(record.UserId, 3)))
			{
				throw new SecurityException("Verification:PasswordAnswers", "The password answers verify failed.");
			}

			//确认新密码是否符合密码规则
			this.OnValidatePassword(newPassword);

			//重新生成密码随机数
			var passwordSalt = this.GetPasswordSalt();

			return this.DataAccess.Update<IUser>(
				new
				{
					Password = PasswordUtility.HashPassword(newPassword, passwordSalt),
					PasswordSalt = passwordSalt,
				}, Condition.Equal(nameof(IUser.UserId), record.UserId)) > 0;
		}

		public string[] GetPasswordQuestions(uint userId)
		{
			//确认指定的用户编号是否有效
			userId = GetUserId(userId);

			var record = this.DataAccess.Select<UserSecretQuestion>(Condition.Equal(nameof(IUser.UserId), userId)).FirstOrDefault();

			if(record.UserId == 0)
				return null;

			return new string[] {
				record.PasswordQuestion1,
				record.PasswordQuestion2,
				record.PasswordQuestion3,
			};
		}

		public string[] GetPasswordQuestions(string identity, string @namespace)
		{
			var record = this.DataAccess.Select<UserSecretQuestion>(MembershipHelper.GetUserIdentityCondition(identity, @namespace)).FirstOrDefault();

			if(record.UserId == 0)
				return null;

			return new string[] {
				record.PasswordQuestion1,
				record.PasswordQuestion2,
				record.PasswordQuestion3,
			};
		}

		public bool SetPasswordQuestionsAndAnswers(uint userId, string password, string[] passwordQuestions, string[] passwordAnswers)
		{
			if(passwordQuestions == null || passwordQuestions.Length < 3)
				throw new ArgumentNullException(nameof(passwordQuestions));

			if(passwordAnswers == null || passwordAnswers.Length < 3)
				throw new ArgumentNullException(nameof(passwordAnswers));

			if(passwordQuestions.Length != passwordAnswers.Length)
				throw new ArgumentException("The password questions and answers count is not equals.");

			//确认指定的用户编号是否有效
			userId = GetUserId(userId);

			//获取用户密码及密码盐
			var token = this.DataAccess.Select<UserPasswordToken>(Condition.Equal(nameof(IUser.UserId), userId)).FirstOrDefault();

			if(token.UserId == 0)
				return false;

			if(!PasswordUtility.VerifyPassword(password, token.Password, token.PasswordSalt))
				throw new SecurityException("Verification:Password", "The password verify failed.");

			return this.DataAccess.Update<IUser>(new
			{
				PasswordQuestion1 = passwordQuestions.Length > 0 ? passwordQuestions[0] : null,
				PasswordAnswer1 = passwordAnswers.Length > 0 ? this.HashPasswordAnswer(passwordAnswers[0], userId, 1) : null,
				PasswordQuestion2 = passwordQuestions.Length > 1 ? passwordQuestions[1] : null,
				PasswordAnswer2 = passwordAnswers.Length > 1 ? this.HashPasswordAnswer(passwordAnswers[1], userId, 2) : null,
				PasswordQuestion3 = passwordQuestions.Length > 2 ? passwordQuestions[2] : null,
				PasswordAnswer3 = passwordAnswers.Length > 2 ? this.HashPasswordAnswer(passwordAnswers[2], userId, 3) : null,
			}, new Condition(nameof(IUser.UserId), userId)) > 0;
		}
		#endregion

		#region 秘密校验
		public bool Verify(uint userId, string type, string secret)
		{
			if(string.IsNullOrWhiteSpace(type))
				throw new ArgumentNullException(nameof(type));

			var verifier = _secretProvider;

			if(verifier == null)
				return false;

			//校验指定的密文
			var succeed = verifier.Verify($"{type}:{userId}", secret, out var extra);

			//如果校验成功并且密文中有附加数据
			if(succeed && (extra != null && extra.Length > 0))
			{
				switch(type)
				{
					case KEY_EMAIL_SECRET:
						this.DataAccess.Update<IUser>(new
						{
							Email = string.IsNullOrWhiteSpace(extra) ? null : extra.Trim(),
							Modification = DateTime.Now,
						}, Condition.Equal(nameof(IUser.UserId), userId));

						break;
					case KEY_PHONE_SECRET:
						this.DataAccess.Update<IUser>(new
						{
							PhoneNumber = string.IsNullOrWhiteSpace(extra) ? null : extra.Trim(),
							Modification = DateTime.Now,
						}, Condition.Equal(nameof(IUser.UserId), userId));

						break;
				}
			}

			return succeed;
		}
		#endregion

		#region 虚拟方法
		protected virtual bool IsVerifyEmailRequired()
		{
			return this.Configuration.VerifyEmailEnabled && _secretProvider != null;
		}

		protected virtual bool IsVerifyPhoneRequired()
		{
			return this.Configuration.VerifyPhoneEnabled && _secretProvider != null;
		}

		protected virtual void OnChangeEmail(IUser user, string email)
		{
			if(user == null)
				return;

			var secretProvider = this.SecretProvider;

			if(secretProvider == null)
			{
				this.DataAccess.Update<IUser>(new
				{
					Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
					Modification = DateTime.Now,
				}, Condition.Equal(nameof(IUser.UserId), user.UserId));
			}
			else
			{
				var secret = secretProvider.Generate($"{KEY_EMAIL_SECRET}:{user.UserId}", email);

				var parameter = new Dictionary<string, object>
				{
					{ "Secret", secret },
					{ "Data", user },
				};

				CommandExecutor.Default.Execute($"email.send -template:{KEY_EMAIL_SECRET} {email}", parameter);
			}
		}

		protected virtual void OnChangePhone(IUser user, string phone)
		{
			if(user == null)
				return;

			var secretProvider = this.SecretProvider;

			if(secretProvider == null)
			{
				this.DataAccess.Update<IUser>(new
				{
					PhoneNumber = string.IsNullOrWhiteSpace(phone) ? null : phone.Trim(),
					Modification = DateTime.Now,
				}, Condition.Equal(nameof(IUser.UserId), user.UserId));
			}
			else
			{
				var secret = secretProvider.Generate($"{KEY_PHONE_SECRET}:{user.UserId}", phone);

				var parameter = new Dictionary<string, object>
				{
					{ "Secret", secret },
					{ "Data", user },
				};

				CommandExecutor.Default.Execute($"sms.send -template:{KEY_PHONE_SECRET} {phone}", parameter);
			}
		}

		protected virtual void OnValidateName(string name)
		{
			var validator = _services?.Resolve<IValidator<string>>("user.name");

			if(validator != null)
				validator.Validate(name, message => throw new SecurityException("username.illegality", message));
		}

		protected virtual void OnValidatePassword(string password)
		{
			var validator = _services?.Resolve<IValidator<string>>("password");

			if(validator != null)
				validator.Validate(password, message => throw new SecurityException("password.illegality", message));
		}
		#endregion

		#region 私有方法
		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private void Censor(string name)
		{
			var censorship = this.Censorship;

			if(censorship != null && censorship.IsBlocked(name, Zongsoft.Security.Censorship.KEY_NAMES, Zongsoft.Security.Censorship.KEY_SENSITIVES))
				throw new CensorshipException(string.Format("Illegal '{0}' name of user.", name));
		}

		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private uint GetUserId(uint userId)
		{
			if(ApplicationContext.Current == null || ApplicationContext.Current.Principal.Identity.IsAuthenticated == false)
				throw new AuthorizationException("No authorization or access to current user credentials.");

			var principal = ApplicationContext.Current.Principal as CredentialPrincipal;

			if(principal == null)
				throw new InvalidOperationException($"The '{ApplicationContext.Current.Principal.GetType().FullName}' is an invalid or unsupported type of security principal.");

			if(userId == 0)
				return principal.Identity.Credential.User.UserId;

			/*
			 * 只有当前用户是如下情况之一，才能操作指定的其他用户：
			 *   1) 指定的用户就是当前用户自己；
			 *   2) 当前用户编号为系统管理员（即当前用户编号为1）；
			 *   3) 当前用户是系统管理员角色(Administrators)成员。
			 */
			if(principal.Identity.Credential.User.UserId == 1 || principal.Identity.Credential.User.UserId == userId || principal.InRole(MembershipHelper.Administrators))
				return userId;

			throw new AuthorizationException($"The current user cannot operate on other user information.");
		}

		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private long GetPasswordSalt()
		{
			return Math.Abs(Zongsoft.Common.RandomGenerator.GenerateInt64());
		}

		private byte[] GetPasswordAnswerSalt(uint userId, int index)
		{
			return Encoding.ASCII.GetBytes(string.Format("Zongsoft.Security.User:{0}:Password.Answer[{1}]", userId.ToString(), index.ToString()));
		}

		private byte[] HashPasswordAnswer(string answer, uint userId, int index)
		{
			if(string.IsNullOrEmpty(answer))
				return null;

			var salt = this.GetPasswordAnswerSalt(userId, index);
			return PasswordUtility.HashPassword(answer, salt);
		}
		#endregion

		[Zongsoft.Data.Entity("Security.User")]
		private struct UserPasswordToken
		{
			public uint UserId;
			public byte[] Password;
			public long PasswordSalt;

			public UserPasswordToken(uint userId, byte[] password, long passwordSalt = 0)
			{
				this.UserId = userId;
				this.Password = password;
				this.PasswordSalt = passwordSalt;
			}
		}

		[Zongsoft.Data.Entity("Security.User")]
		private struct UserSecretQuestion
		{
			public uint UserId;
			public string PasswordQuestion1;
			public string PasswordQuestion2;
			public string PasswordQuestion3;
		}

		[Zongsoft.Data.Entity("Security.User")]
		private struct UserSecretAnswer
		{
			public uint UserId;
			public byte[] PasswordAnswer1;
			public byte[] PasswordAnswer2;
			public byte[] PasswordAnswer3;
		}
	}
}
