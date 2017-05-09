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
using Zongsoft.Services;
using Zongsoft.Runtime.Caching;

namespace Zongsoft.Security.Membership
{
	public class UserProvider : MarshalByRefObject, IUserProvider
	{
		#region 成员字段
		private IDataAccess _dataAccess;
		private ISequence _sequence;
		private ICache _cache;
		private ICensorship _censorship;
		#endregion

		#region 构造函数
		public UserProvider()
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
		public ICache Cache
		{
			get
			{
				return _cache;
			}
			set
			{
				_cache = value;
			}
		}

		[Zongsoft.Services.ServiceDependency]
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
			if(@namespace == null)
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
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetPhoneNumber(uint userId, string phoneNumber)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					PhoneNumber = string.IsNullOrWhiteSpace(phoneNumber) ? null : phoneNumber.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
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
			this.VerifyName(name);

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
			this.VerifyName(user.Name);

			//确保用户名是审核通过的
			this.Censor(user.Name);

			//确认指定用户的用户名、手机号、邮箱地址是否已经存在
			this.EnsureConflict(user, null, false);

			if(user.UserId < 1)
				user.UserId = (uint)this.Sequence.Increment(MembershipHelper.SEQUENCE_USERID, 1, MembershipHelper.MINIMUM_ID);

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
				this.VerifyName(user.Name);

				//确保用户名是审核通过的
				this.Censor(user.Name);

				//确认指定用户的用户名、手机号、邮箱地址是否已经存在
				this.EnsureConflict(user, null, false);
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
					this.VerifyName(user.Name);

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
			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, new ConditionCollection(ConditionCombination.And, condition, Condition.NotEqual("Password", null)));
		}

		public bool ChangePassword(uint userId, string oldPassword, string newPassword)
		{
			byte[] storedPassword;
			byte[] storedPasswordSalt;

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
				}, new Condition("UserId", userId)) > 0;
		}

		public uint ForgetPassword(string identity, string @namespace, string secret, TimeSpan? timeout = null)
		{
			if(string.IsNullOrWhiteSpace(secret))
				throw new ArgumentNullException("secret");

			var cache = this.Cache;

			if(cache == null)
				throw new InvalidOperationException("The dependent cache is null.");

			uint userId;
			if(!MembershipHelper.GetUserId(this.DataAccess, identity, @namespace, out userId))
				return 0;

			cache.SetValue(this.GetCacheKeyOfResetPassword(userId), secret, timeout.HasValue && timeout.Value > TimeSpan.Zero ? timeout.Value : TimeSpan.FromHours(1));

			return userId;
		}

		public bool ResetPassword(uint userId, string secret, string newPassword = null)
		{
			if(string.IsNullOrEmpty(secret))
				return false;

			var cache = this.Cache;

			if(cache == null)
				throw new InvalidOperationException("The dependent cache is null.");

			var cachedSecret = cache.GetValue(this.GetCacheKeyOfResetPassword(userId)) as string;
			var succeed = cachedSecret != null && string.Equals(secret, cachedSecret, StringComparison.Ordinal);

			if(succeed && newPassword != null && newPassword.Length > 0)
			{
				//重新生成密码随机数
				var passwordSalt = Zongsoft.Common.RandomGenerator.Generate(8);

				var affectedRows = this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
					new
					{
						Password = PasswordUtility.HashPassword(newPassword, passwordSalt),
						PasswordSalt = passwordSalt,
					}, new Condition("UserId", userId));

				if(affectedRows > 0)
					cache.Remove(this.GetCacheKeyOfResetPassword(userId));

				return affectedRows > 0;
			}

			return succeed;
		}

		public bool ResetPassword(string identity, string @namespace, string secret, string newPassword = null)
		{
			if(string.IsNullOrWhiteSpace(identity) || string.IsNullOrWhiteSpace(secret))
				return false;

			var cache = this.Cache;

			if(cache == null)
				throw new InvalidOperationException("The dependent cache is null.");

			uint userId = 0;
			if(!MembershipHelper.GetUserId(this.DataAccess, identity, @namespace, out userId))
				return false;

			var cachedSecret = cache.GetValue(this.GetCacheKeyOfResetPassword(userId)) as string;
			var succeed = cachedSecret != null && string.Equals(cachedSecret, secret, StringComparison.Ordinal);

			if(succeed && newPassword != null && newPassword.Length > 0)
			{
				//重新生成密码随机数
				var passwordSalt = Zongsoft.Common.RandomGenerator.Generate(8);

				var affectedRows = this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
					new
					{
						Password = PasswordUtility.HashPassword(newPassword, passwordSalt),
						PasswordSalt = passwordSalt,
					}, new Condition("UserId", userId));

				if(affectedRows > 0)
					cache.Remove(this.GetCacheKeyOfResetPassword(userId));

				return affectedRows > 0;
			}

			return succeed;
		}

		public bool ResetPassword(string identity, string @namespace, string[] passwordAnswers, string newPassword = null)
		{
			if(string.IsNullOrWhiteSpace(identity) || passwordAnswers == null || passwordAnswers.Length < 3)
				return false;

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
					}, new Condition("UserId", userId)) > 0;
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

		public bool SetPasswordOptions(uint userId, bool changePasswordOnFirstTime = false, byte maxInvalidPasswordAttempts = 3, byte minRequiredPasswordLength = 6, TimeSpan? passwordAttemptWindow = null, DateTime? passwordExpires = null)
		{
			var dictionary = new Dictionary<string, object>()
			{
				{ "ChangePasswordOnFirstTime", changePasswordOnFirstTime },
				{ "MaxInvalidPasswordAttempts", maxInvalidPasswordAttempts },
				{ "MinRequiredPasswordLength", minRequiredPasswordLength },
			};

			if(passwordAttemptWindow.HasValue)
				dictionary.Add("PasswordAttemptWindow", passwordAttemptWindow.Value);

			if(passwordExpires.HasValue)
				dictionary.Add("PasswordExpires", passwordExpires.Value);

			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER, dictionary, new Condition("UserId", userId)) > 0;
		}
		#endregion

		#region 虚拟方法
		protected virtual void VerifyName(string name)
		{
			Utility.VerifyName(name);
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

		private string GetCacheKeyOfResetPassword(uint userId)
		{
			return "Zongsoft.Security.Membership.ResetPassword:" + userId.ToString();
		}
		#endregion
	}
}
