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
		public bool Approve(int userId, bool approved = true)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Approved = approved,
					ApprovedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool Suspend(int userId, bool suspended = true)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Suspended = suspended,
					SuspendedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public User GetUser(int userId)
		{
			return MembershipHelper.GetUser(this.DataAccess, userId);
		}

		public User GetUser(string identity, string @namespace)
		{
			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			return this.DataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, condition).FirstOrDefault();
		}

		public IEnumerable<User> GetAllUsers(string @namespace, Paging paging = null)
		{
			if(string.IsNullOrWhiteSpace(@namespace))
				return this.DataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, null, paging);
			else
				return this.DataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, Condition.Equal("Namespace", MembershipHelper.TrimNamespace(@namespace)), paging);
		}

		public bool Exists(int userId)
		{
			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, Condition.Equal("UserId", userId));
		}

		public bool Exists(string identity, string @namespace)
		{
			if(string.IsNullOrWhiteSpace(identity))
				return false;

			MembershipHelper.UserIdentityType identityType;
			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace, out identityType);

			if(identityType == MembershipHelper.UserIdentityType.Name)
			{
				//确保用户名是审核通过的
				this.Censor(identity);
			}

			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, condition);
		}

		public bool SetAvatar(int userId, string avatar)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Avatar = string.IsNullOrWhiteSpace(avatar) ? null : avatar.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetEmail(int userId, string email)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetPhoneNumber(int userId, string phoneNumber)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					PhoneNumber = string.IsNullOrWhiteSpace(phoneNumber) ? null : phoneNumber.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetName(int userId, string name)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new ArgumentNullException("name");

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

		public bool SetFullName(int userId, string fullName)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					FullName = string.IsNullOrWhiteSpace(fullName) ? null : fullName.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetPrincipalId(int userId, string principalId)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					PrincipalId = string.IsNullOrWhiteSpace(principalId) ? null : principalId.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetDescription(int userId, string description)
		{
			return this.DataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public int DeleteUsers(params int[] userIds)
		{
			if(userIds == null || userIds.Length < 1)
				return 0;

			return this.DataAccess.Delete(MembershipHelper.DATA_ENTITY_USER, new Condition("UserId", userIds, ConditionOperator.In));
		}

		public bool CreateUser(User user, string password)
		{
			if(user == null)
				throw new ArgumentNullException("user");

			if(string.IsNullOrWhiteSpace(user.Name))
				throw new ArgumentException("The user name is empty.");

			//确保用户名是审核通过的
			this.Censor(user.Name);

			if(user.UserId < 1)
				user.UserId = (int)this.Sequence.GetSequenceNumber(MembershipHelper.SEQUENCE_USERID, 1, MembershipHelper.MINIMUM_ID);

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

				//确保用户名是审核通过的
				this.Censor(user.Name);
			}

			foreach(var user in users)
			{
				//处理未指定有效编号的用户对象
				if(user != null && user.UserId < 1)
					user.UserId = (int)this.Sequence.GetSequenceNumber(MembershipHelper.SEQUENCE_USERID, 1, MembershipHelper.MINIMUM_ID);
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

					//确保用户名是审核通过的
					this.Censor(user.Name);
				}
			}

			return this.DataAccess.UpdateMany(MembershipHelper.DATA_ENTITY_USER, users, scope);
		}
		#endregion

		#region 密码管理
		public bool HasPassword(int userId)
		{
			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_USER,
										  Condition.Equal("UserId", userId) & Condition.NotEqual("Password", null));
		}

		public bool HasPassword(string identity, string @namespace)
		{
			var condition = MembershipHelper.GetUserIdentityCondition(identity, @namespace);
			return this.DataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, new ConditionCollection(ConditionCombination.And, condition, Condition.NotEqual("Password", null)));
		}

		public bool ChangePassword(int userId, string oldPassword, string newPassword)
		{
			byte[] storedPassword;
			byte[] storedPasswordSalt;
			bool isApproved, isSuspended;

			if(!MembershipHelper.GetPassword(this.DataAccess, userId, out storedPassword, out storedPasswordSalt, out isApproved, out isSuspended))
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

		public int ForgetPassword(string identity, string @namespace, string secret, TimeSpan? timeout = null)
		{
			if(string.IsNullOrWhiteSpace(secret))
				throw new ArgumentNullException("secret");

			var cache = this.Cache;

			if(cache == null)
				throw new InvalidOperationException("The dependent cache is null.");

			int userId;
			if(!MembershipHelper.GetUserId(this.DataAccess, identity, @namespace, out userId))
				return -1;

			cache.SetValue(this.GetCacheKeyOfResetPassword(userId), secret, timeout.HasValue && timeout.Value > TimeSpan.Zero ? timeout.Value : TimeSpan.FromHours(1));

			return userId;
		}

		public bool ResetPassword(int userId, string secret, string newPassword = null)
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

			var userId = 0;
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

			var userId = Zongsoft.Common.Convert.ConvertValue<int>(record["UserId"]);

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

		public string[] GetPasswordQuestions(int userId)
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

		public bool SetPasswordQuestionsAndAnswers(int userId, string password, string[] passwordQuestions, string[] passwordAnswers)
		{
			if(passwordQuestions == null || passwordQuestions.Length < 3)
				throw new ArgumentNullException("passwordQuestions");

			if(passwordAnswers == null || passwordAnswers.Length < 3)
				throw new ArgumentNullException("passwordAnswers");

			if(passwordQuestions.Length != passwordAnswers.Length)
				throw new ArgumentException();

			byte[] storedPassword;
			byte[] storedPasswordSalt;
			bool isApproved, isSuspended;

			if(!MembershipHelper.GetPassword(this.DataAccess, userId, out storedPassword, out storedPasswordSalt, out isApproved, out isSuspended))
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

		public bool SetPasswordOptions(int userId, bool changePasswordOnFirstTime = false, byte maxInvalidPasswordAttempts = 3, byte minRequiredPasswordLength = 6, TimeSpan? passwordAttemptWindow = null, DateTime? passwordExpires = null)
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

		#region 私有方法
		private void Censor(string name)
		{
			var censorship = this.Censorship;

			if(censorship != null && censorship.IsBlocked(name, Zongsoft.Security.Censorship.KEY_NAMES, Zongsoft.Security.Censorship.KEY_SENSITIVES))
				throw new CensorshipException(string.Format("Illegal '{0}' name of user.", name));
		}

		private byte[] GetPasswordAnswerSalt(int userId, int index)
		{
			return Encoding.ASCII.GetBytes(string.Format("Zongsoft.Security.User:{0}:PasswordAnswer[{1}]", userId.ToString(), index.ToString()));
		}

		private byte[] HashPasswordAnswer(string answer, int userId, int index)
		{
			if(string.IsNullOrEmpty(answer))
				return null;

			var salt = this.GetPasswordAnswerSalt(userId, index);
			return PasswordUtility.HashPassword(answer, salt);
		}

		private string GetCacheKeyOfResetPassword(int userId)
		{
			return "Zongsoft.Security.Membership.ResetPassword:" + userId.ToString();
		}
		#endregion
	}
}
