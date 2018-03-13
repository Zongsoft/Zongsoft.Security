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
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Zongsoft.Data;
using Zongsoft.Common;
using Zongsoft.Communication;
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
		private ISequence _sequence;
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
				if(value == null)
					throw new ArgumentNullException();

				_dataAccess = value;
			}
		}

		[ServiceDependency]
		public ISequence Sequence
		{
			get
			{
				return _sequence;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_sequence = value;
			}
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
		public User GetUser(uint userId)
		{
			return MembershipHelper.GetUser(this.DataAccess, userId);
		}

		public User GetUser(string identity, string @namespace)
		{
			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			return this.DataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, condition).FirstOrDefault();
		}

		public IEnumerable<User> GetUsers(string @namespace, Paging paging = null)
		{
			if(@namespace == "*")
				return this.DataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER);
			else
				return this.DataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, MembershipHelper.GetNamespaceCondition(@namespace), paging);
		}

		public bool Exists(uint userId)
		{
			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, Condition.Equal("UserId", userId));
		}

		public bool Exists(string identity, string @namespace)
		{
			if(string.IsNullOrWhiteSpace(identity))
				return false;

			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, condition);
		}

		public bool SetAvatar(uint userId, string avatar)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Avatar = string.IsNullOrWhiteSpace(avatar) ? null : avatar.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetEmail(uint userId, string email)
		{
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

			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
					ModifiedTime = DateTime.Now,
				}, Condition.Equal("UserId", userId)) > 0;
		}

		public bool SetPhoneNumber(uint userId, string phoneNumber)
		{
			//判断是否电话号码是否需要校验
			if(this.IsVerifyEmailRequired())
			{
				//获取指定编号的用户
				var user = this.GetUser(userId);

				if(user == null)
					return false;

				//发送电话号码更改的校验通知
				this.OnChangeEmail(user, phoneNumber);

				//返回成功
				return true;
			}

			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					PhoneNumber = string.IsNullOrWhiteSpace(phoneNumber) ? null : phoneNumber.Trim(),
					ModifiedTime = DateTime.Now,
				}, Condition.Equal("UserId", userId)) > 0;
		}

		public bool SetNamespace(uint userId, string @namespace)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Namespace = string.IsNullOrWhiteSpace(@namespace) ? null : @namespace.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public int SetNamespaces(string oldNamespace, string newNamespace)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Namespace = string.IsNullOrWhiteSpace(newNamespace) ? null : newNamespace.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("Namespace", oldNamespace));
		}

		public bool SetName(uint userId, string name)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new ArgumentNullException("name");

			//验证指定的名称是否合法
			this.OnValidateName(name);

			//确保用户名是审核通过的
			this.Censor(name);

			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Name = name.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetFullName(uint userId, string fullName)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					FullName = string.IsNullOrWhiteSpace(fullName) ? null : fullName.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetPrincipalId(uint userId, string principalId)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					PrincipalId = string.IsNullOrWhiteSpace(principalId) ? null : principalId.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetStatus(uint userId, UserStatus status)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Status = status,
					StatusTimestamp = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetDescription(uint userId, string description)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public int DeleteUsers(params uint[] userIds)
		{
			if(userIds == null || userIds.Length < 1)
				return 0;

			int result = 0;

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				result = this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_USER, Condition.In("UserId", userIds));

				if(result > 0)
				{
					this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_MEMBER, Condition.Equal("MemberType", MemberType.User) & Condition.In("MemberId", userIds));
					this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_PERMISSION, Condition.Equal("MemberType", MemberType.User) & Condition.In("MemberId", userIds));
					this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_PERMISSION_FILTER, Condition.Equal("MemberType", MemberType.User) & Condition.In("MemberId", userIds));
				}

				transaction.Commit();
			}

			return result;
		}

		public bool CreateUser(User user, string password)
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

			//确认指定用户的用户名、手机号、邮箱地址是否已经存在
			this.EnsureConflict(user, null, false);

			if(user.UserId < 1)
				user.UserId = (uint)this.Sequence.Increment(MembershipHelper.SEQUENCE_USERID, 1, MembershipHelper.MINIMUM_ID);

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
			user.CreatedTime = DateTime.Now;

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				if(this.DataAccess.Insert(MembershipHelper.DATA_ENTITY_USER, user) < 1)
					return false;

				//有效的密码不能为空或全空格字符串
				if(!string.IsNullOrWhiteSpace(password))
				{
					//生成密码随机数
					var passwordSalt = Zongsoft.Common.RandomGenerator.Generate(8);

					this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER, new
					{
						Password = PasswordUtility.HashPassword(password, passwordSalt),
						PasswordSalt = passwordSalt,
					}, new Condition("UserId", user.UserId));
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

		public int CreateUsers(IEnumerable<User> users)
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

				//确认指定用户的用户名、手机号、邮箱地址是否已经存在
				this.EnsureConflict(user, null, false);

				//更新创建时间
				user.CreatedTime = DateTime.Now;
			}

			foreach(var user in users)
			{
				//处理未指定有效编号的用户对象
				if(user != null && user.UserId < 1)
					user.UserId = (uint)this.Sequence.Increment(MembershipHelper.SEQUENCE_USERID, 1, MembershipHelper.MINIMUM_ID);
			}

			return this.DataAccess.InsertMany(MembershipHelper.DATA_ENTITY_USER, users);
		}

		public int UpdateUsers(params User[] users)
		{
			if(users == null || users.Length < 1)
				return 0;

			return this.UpdateUsers((IEnumerable<User>)users, null);
		}

		public int UpdateUsers(IEnumerable<User> users, string scope = null)
		{
			if(users == null)
				return 0;

			if(string.IsNullOrWhiteSpace(scope))
				scope = "!Name, !Email, !PhoneNumber, !CreatorId, !CreatedTime";
			else
				scope += ", !Name, !Email, !PhoneNumber, !CreatorId, !CreatedTime";

			foreach(var user in users)
			{
				if(user == null)
					continue;

				//只有当要更新的范围包含“Name”用户名才需要验证该属性值
				if(MembershipHelper.InScope<User>(scope, "Name"))
				{
					if(string.IsNullOrWhiteSpace(user.Name))
						throw new ArgumentException("The user name is empty.");

					//验证指定的名称是否合法
					this.OnValidateName(user.Name);

					//确保用户名是审核通过的
					this.Censor(user.Name);
				}

				//确认指定用户的用户名、手机号、邮箱地址是否已经存在
				this.EnsureConflict(user, scope, true);
			}

			return this.DataAccess.UpdateMany(MembershipHelper.DATA_ENTITY_USER, users, scope);
		}
		#endregion

		#region 密码管理
		public bool HasPassword(uint userId)
		{
			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_USER,
										  Condition.Equal("UserId", userId) & Condition.NotEqual("Password", null));
		}

		public bool HasPassword(string identity, string @namespace)
		{
			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, ConditionCollection.And(condition, Condition.NotEqual("Password", null)));
		}

		public bool ChangePassword(uint userId, string oldPassword, string newPassword)
		{
			byte[] storedPassword;
			byte[] storedPasswordSalt;

			//确认新密码是否符合密码规则
			this.OnValidatePassword(newPassword);

			if(!MembershipHelper.GetPassword(this.DataAccess, userId, out storedPassword, out storedPasswordSalt))
				return false;

			if(!PasswordUtility.VerifyPassword(oldPassword, storedPassword, storedPasswordSalt))
				return false;

			//重新生成密码随机数
			storedPasswordSalt = Zongsoft.Common.RandomGenerator.Generate(8);

			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Password = PasswordUtility.HashPassword(newPassword, storedPasswordSalt),
					PasswordSalt = storedPasswordSalt,
				}, Condition.Equal("UserId", userId)) > 0;
		}

		public uint ForgetPassword(string identity, string @namespace)
		{
			var secretor = this.SecretProvider;

			if(secretor == null)
				throw new InvalidOperationException("Missing secret provider.");

			//解析用户标识的查询条件
			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace, out var identityType);

			//如果查询条件解析失败或用户标识为用户名，则抛出不支持的异常
			if(condition == null || identityType == MembershipHelper.UserIdentityType.Name)
				throw new NotSupportedException("Invalid user identity for the forget password operation.");

			//获取指定标识的用户信息
			var user = _dataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, condition).FirstOrDefault();

			if(user == null)
				return 0;

			string secret = null;
			object parameter = null;

			switch(identityType)
			{
				case MembershipHelper.UserIdentityType.Email:
					//生成校验密文
					secret = secretor.Generate($"{KEY_FORGET_SECRET}:{user.UserId}");

					//构造发送的邮件模板的参数
					parameter = new Dictionary<string, object>
					{
						{ "Secret", secret },
						{ "Data", user },
					};

					//发送忘记密码的邮件通知
					CommandExecutor.Default.Execute($"email.send -template:{KEY_FORGET_SECRET}", parameter);

					break;
				case MembershipHelper.UserIdentityType.Phone:
					//生成校验密文
					secret = secretor.Generate($"{KEY_FORGET_SECRET}:{user.UserId}");

					//构造发送的短信模板的参数
					parameter = new Dictionary<string, object>
					{
						{ "Secret", secret },
						{ "Data", user },
					};

					//发送忘记密码的短信通知
					CommandExecutor.Default.Execute($"sms.send -template:{KEY_FORGET_SECRET}", parameter);

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

			//如果重置密码的校验码验证成功
			if(secretProvider.Verify($"{KEY_FORGET_SECRET}:{userId}", secret))
			{
				//确认新密码是否符合密码规则
				this.OnValidatePassword(newPassword);

				IDictionary<string, object> data;

				if(string.IsNullOrWhiteSpace(newPassword))
				{
					data = new Dictionary<string, object>()
					{
						{ "Password", null },
						{ "PasswordSalt", null },
					};
				}
				else
				{
					//重新生成密码随机数
					var passwordSalt = RandomGenerator.Generate(8);

					data = new Dictionary<string, object>()
					{
						{ "Password", PasswordUtility.HashPassword(newPassword, passwordSalt)},
						{ "PasswordSalt", passwordSalt},
					};
				}

				//提交修改密码的更新操作
				return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER, data, Condition.Equal("UserId", userId)) > 0;
			}

			//重置密码校验失败，抛出异常
			throw new SecurityException("verify.fail", "Invalid secret of verification.");
		}

		public bool ResetPassword(string identity, string @namespace, string[] passwordAnswers, string newPassword = null)
		{
			if(string.IsNullOrWhiteSpace(identity) || passwordAnswers == null || passwordAnswers.Length < 3)
				return false;

			//确认新密码是否符合密码规则
			this.OnValidatePassword(newPassword);

			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			var record = this.DataAccess.Select<IDictionary<string, object>>(MembershipHelper.DATA_ENTITY_USER, condition, "!, UserId, PasswordAnswer1, PasswordAnswer2, PasswordAnswer3").FirstOrDefault();

			if(record == null || record.Count < 1)
				return false;

			var userId = Zongsoft.Common.Convert.ConvertValue<uint>(record["UserId"]);

			var succeed = PasswordUtility.VerifyPassword(passwordAnswers[0], record["PasswordAnswer1"] as byte[], this.GetPasswordAnswerSalt(userId, 1)) &&
			              PasswordUtility.VerifyPassword(passwordAnswers[1], record["PasswordAnswer2"] as byte[], this.GetPasswordAnswerSalt(userId, 2)) &&
			              PasswordUtility.VerifyPassword(passwordAnswers[2], record["PasswordAnswer3"] as byte[], this.GetPasswordAnswerSalt(userId, 3));

			if(succeed && newPassword != null && newPassword.Length > 0)
			{
				//重新生成密码随机数
				var passwordSalt = Zongsoft.Common.RandomGenerator.Generate(8);

				return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
					new
					{
						Password = PasswordUtility.HashPassword(newPassword, passwordSalt),
						PasswordSalt = passwordSalt,
					}, Condition.Equal("UserId", userId)) > 0;
			}

			return succeed;
		}

		public string[] GetPasswordQuestions(uint userId)
		{
			var record = this.DataAccess.Select<IDictionary<string, object>>(MembershipHelper.DATA_ENTITY_USER, new Condition("UserId", userId), "!, UserId, PasswordQuestion1, PasswordQuestion2, PasswordQuestion3").FirstOrDefault();

			if(record == null)
				return null;

			var result = new string[] {
				record["PasswordQuestion1"] as string,
				record["PasswordQuestion2"] as string,
				record["PasswordQuestion3"] as string,
			};

			return result;
		}

		public string[] GetPasswordQuestions(string identity, string @namespace)
		{
			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			var record = this.DataAccess.Select<IDictionary<string, object>>(MembershipHelper.DATA_ENTITY_USER, condition, "!, UserId, PasswordQuestion1, PasswordQuestion2, PasswordQuestion3").FirstOrDefault();

			if(record == null)
				return null;

			var result = new string[] {
				record["PasswordQuestion1"] as string,
				record["PasswordQuestion2"] as string,
				record["PasswordQuestion3"] as string,
			};

			return result;
		}

		public bool SetPasswordQuestionsAndAnswers(uint userId, string password, string[] passwordQuestions, string[] passwordAnswers)
		{
			if(passwordQuestions == null || passwordQuestions.Length < 3)
				throw new ArgumentNullException("passwordQuestions");

			if(passwordAnswers == null || passwordAnswers.Length < 3)
				throw new ArgumentNullException("passwordAnswers");

			if(passwordQuestions.Length != passwordAnswers.Length)
				throw new ArgumentException();

			byte[] storedPassword;
			byte[] storedPasswordSalt;

			if(!MembershipHelper.GetPassword(this.DataAccess, userId, out storedPassword, out storedPasswordSalt))
				return false;

			if(!PasswordUtility.VerifyPassword(password, storedPassword, storedPasswordSalt))
				return false;

			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER, new
			{
				PasswordQuestion1 = passwordQuestions.Length > 0 ? passwordQuestions[0] : null,
				PasswordAnswer1 = passwordAnswers.Length > 0 ? this.HashPasswordAnswer(passwordAnswers[0], userId, 1) : null,
				PasswordQuestion2 = passwordQuestions.Length > 1 ? passwordQuestions[1] : null,
				PasswordAnswer2 = passwordAnswers.Length > 1 ? this.HashPasswordAnswer(passwordAnswers[1], userId, 2) : null,
				PasswordQuestion3 = passwordQuestions.Length > 2 ? passwordQuestions[2] : null,
				PasswordAnswer3 = passwordAnswers.Length > 2 ? this.HashPasswordAnswer(passwordAnswers[2], userId, 3) : null,
			}, new Condition("UserId", userId)) > 0;
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
						this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER, new
						{
							Email = string.IsNullOrWhiteSpace(extra) ? null : extra.Trim(),
							ModifiedTime = DateTime.Now,
						}, Condition.Equal("UserId", userId));

						break;
					case KEY_PHONE_SECRET:
						this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER, new
						{
							PhoneNumber = string.IsNullOrWhiteSpace(extra) ? null : extra.Trim(),
							ModifiedTime = DateTime.Now,
						}, Condition.Equal("UserId", userId));

						break;
				}
			}

			return succeed;
		}
		#endregion

		#region 虚拟方法
		protected virtual bool IsVerifyEmailRequired()
		{
			return _secretProvider != null;
		}

		protected virtual bool IsVerifyPhoneRequired()
		{
			return _secretProvider != null;
		}

		protected virtual void OnChangeEmail(User user, string email)
		{
			if(user == null)
				return;

			var secretProvider = this.SecretProvider;

			if(secretProvider == null)
			{
				this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER, new
				{
					Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
					ModifiedTime = DateTime.Now,
				}, Condition.Equal("UserId", user.UserId));
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

		protected virtual void OnChangePhone(User user, string phone)
		{
			if(user == null)
				return;

			var secretProvider = this.SecretProvider;

			if(secretProvider == null)
			{
				this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER, new
				{
					PhoneNumber = string.IsNullOrWhiteSpace(phone) ? null : phone.Trim(),
					ModifiedTime = DateTime.Now,
				}, Condition.Equal("UserId", user.UserId));
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
				validator.Validate(name, (key, message) => throw new SecurityException("username.illegality", message));
		}

		protected virtual void OnValidatePassword(string password)
		{
			var validator = _services?.Resolve<IValidator<string>>("password");

			if(validator != null)
				validator.Validate(password, (key, message) => throw new SecurityException("password.illegality", message));
		}
		#endregion

		#region 私有方法
		private void Censor(string name)
		{
			var censorship = this.Censorship;

			if(censorship != null && censorship.IsBlocked(name, Zongsoft.Security.Censorship.KEY_NAMES, Zongsoft.Security.Censorship.KEY_SENSITIVES))
				throw new CensorshipException(string.Format("Illegal '{0}' name of user.", name));
		}

		private void EnsureConflict(User user, string scope, bool isUpdate)
		{
			var ns = MembershipHelper.GetNamespaceCondition(user.Namespace);
			var conditions = new ConditionCollection(ConditionCombination.Or);

			if(!string.IsNullOrWhiteSpace(user.Name) && MembershipHelper.InScope<User>(scope, "Name"))
				conditions.Add(ns & Condition.Equal("Name", user.Name));
			if(!string.IsNullOrWhiteSpace(user.Email) && MembershipHelper.InScope<User>(scope, "Email"))
				conditions.Add(ns & Condition.Equal("Email", user.Email));
			if(!string.IsNullOrWhiteSpace(user.PhoneNumber) && MembershipHelper.InScope<User>(scope, "PhoneNumber"))
				conditions.Add(ns & Condition.Equal("PhoneNumber", user.PhoneNumber));

			if(isUpdate && conditions.Count > 0)
				conditions = Condition.NotEqual("UserId", user.UserId) & conditions;

			if(conditions.Count > 0 && this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, conditions))
				throw new DataConflictException(Zongsoft.Resources.ResourceUtility.GetString("Text.UserConflict"));
		}

		private byte[] GetPasswordAnswerSalt(uint userId, int index)
		{
			return Encoding.ASCII.GetBytes(string.Format("Zongsoft.Security.User:{0}:PasswordAnswer[{1}]", userId.ToString(), index.ToString()));
		}

		private byte[] HashPasswordAnswer(string answer, uint userId, int index)
		{
			if(string.IsNullOrEmpty(answer))
				return null;

			var salt = this.GetPasswordAnswerSalt(userId, index);
			return PasswordUtility.HashPassword(answer, salt);
		}
		#endregion
	}
}
