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
using Zongsoft.Options;

namespace Zongsoft.Security.Membership
{
	public class UserProvider : Zongsoft.Services.ServiceBase, IUserProvider
	{
		#region 成员字段
		private ICensorship _censorship;
		#endregion

		#region 构造函数
		public UserProvider(Zongsoft.Services.IServiceProvider serviceProvider) : base(serviceProvider)
		{
		}
		#endregion

		#region 公共属性
		[Zongsoft.Services.Service]
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
			var dataAccess = this.EnsureService<IDataAccess>();

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Approved = approved,
					ApprovedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool Suspend(int userId, bool suspended = true)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Suspended = suspended,
					SuspendedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public User GetUser(int userId)
		{
			var dataAccess = this.EnsureService<IDataAccess>();
			return MembershipHelper.GetUser(dataAccess, userId);
		}

		public User GetUser(string identity, string @namespace)
		{
			var dataAccess = this.EnsureService<IDataAccess>();
			var conditions = MembershipHelper.GetUserIdentityConditions(identity, @namespace);
			return dataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, conditions).FirstOrDefault();
		}

		public IEnumerable<User> GetAllUsers(string @namespace, Paging paging = null)
		{
			var dataAccess = this.EnsureService<IDataAccess>();
			return dataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, Condition.Equal("Namespace", MembershipHelper.TrimNamespace(@namespace)), paging);
		}

		public bool Exists(int userId)
		{
			if(userId == 0)
				return true;

			var dataAccess = this.EnsureService<IDataAccess>();
			return dataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, new Condition("UserId", userId));
		}

		public bool Exists(string identity, string @namespace)
		{
			if(string.IsNullOrWhiteSpace(identity))
				return false;

			var dataAccess = this.EnsureService<IDataAccess>();
			MembershipHelper.UserIdentityType identityType;
			var conditions = MembershipHelper.GetUserIdentityConditions(identity, @namespace, out identityType);

			if(identityType == MembershipHelper.UserIdentityType.Name)
			{
				//确保用户名是审核通过的
				this.Censor(identity);
			}

			return dataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, conditions);
		}

		public bool SetAvatar(int userId, string avatar)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Avatar = string.IsNullOrWhiteSpace(avatar) ? null : avatar.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetEmail(int userId, string email)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetPhoneNumber(int userId, string phoneNumber)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
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

			var dataAccess = this.EnsureService<IDataAccess>();

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					Name = name.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetFullName(int userId, string fullName)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					FullName = string.IsNullOrWhiteSpace(fullName) ? null : fullName.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetPrincipalId(int userId, string principalId)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new
				{
					PrincipalId = string.IsNullOrWhiteSpace(principalId) ? null : principalId.Trim(),
					ModifiedTime = DateTime.Now,
				},
				new Condition("UserId", userId)) > 0;
		}

		public bool SetDescription(int userId, string description)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
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

			var dataAccess = this.EnsureService<IDataAccess>();
			return dataAccess.Delete(MembershipHelper.DATA_ENTITY_USER, new Condition("UserId", userIds, ConditionOperator.In));
		}

		public bool CreateUser(User user, string password)
		{
			if(user == null)
				throw new ArgumentNullException("user");

			if(string.IsNullOrWhiteSpace(user.Name))
				throw new ArgumentException("The user name is empty.");

			//确保用户名是审核通过的
			this.Censor(user.Name);

			var dataAccess = this.EnsureService<IDataAccess>();

			if(user.UserId < 1)
				user.UserId = (int)this.EnsureService<Zongsoft.Common.ISequence>().GetSequenceNumber(MembershipHelper.SEQUENCE_USERID, 1, MembershipHelper.MINIMUM_ID);

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				if(dataAccess.Insert(MembershipHelper.DATA_ENTITY_USER, user) < 1)
					return false;

				if(password != null && password.Length > 0)
				{
					//生成密码随机数
					var passwordSalt = Zongsoft.Common.RandomGenerator.Generate(8);

					dataAccess.Update(MembershipHelper.DATA_ENTITY_USER, new
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
					user.UserId = (int)this.EnsureService<Zongsoft.Common.ISequence>().GetSequenceNumber(MembershipHelper.SEQUENCE_USERID, 1, MembershipHelper.MINIMUM_ID);
			}

			var dataAccess = this.EnsureService<IDataAccess>();
			return dataAccess.Insert(MembershipHelper.DATA_ENTITY_USER, users);
		}

		public int UpdateUsers(params User[] users)
		{
			if(users == null || users.Length < 1)
				return 0;

			return this.UpdateUsers((IEnumerable<User>)users);
		}

		public int UpdateUsers(IEnumerable<User> users)
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

			var dataAccess = this.EnsureService<IDataAccess>();
			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER, users);
		}
		#endregion

		#region 密码管理
		public bool HasPassword(int userId)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			return dataAccess.Exists(MembershipHelper.DATA_ENTITY_USER,
				new ConditionCollection(ConditionCombine.And,
					new Condition("UserId", userId),
					new Condition("Password", null, ConditionOperator.NotEqual)));
		}

		public bool HasPassword(string identity, string @namespace)
		{
			var dataAccess = this.EnsureService<IDataAccess>();
			var conditions = MembershipHelper.GetUserIdentityConditions(identity, @namespace);

			conditions.Add(new Condition("Password", null, ConditionOperator.NotEqual));

			return dataAccess.Exists(MembershipHelper.DATA_ENTITY_USER, conditions);
		}

		public bool ChangePassword(int userId, string oldPassword, string newPassword)
		{
			var dataAccess = this.EnsureService<IDataAccess>();

			byte[] storedPassword;
			byte[] storedPasswordSalt;
			bool isApproved, isSuspended;

			if(!MembershipHelper.GetPassword(dataAccess, userId, out storedPassword, out storedPasswordSalt, out isApproved, out isSuspended))
				return false;

			if(!PasswordUtility.VerifyPassword(oldPassword, storedPassword, storedPasswordSalt))
				return false;

			//重新生成密码随机数
			storedPasswordSalt = Zongsoft.Common.RandomGenerator.Generate(8);

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
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

			int userId;
			var dataAccess = this.EnsureService<IDataAccess>();

			if(!MembershipHelper.GetUserId(dataAccess, identity, @namespace, out userId))
				return -1;

			var cache = this.EnsureService<Zongsoft.Runtime.Caching.ICache>();

			cache.SetValue(this.GetCacheKeyOfResetPassword(userId), secret, timeout.HasValue && timeout.Value > TimeSpan.Zero ? timeout.Value : TimeSpan.FromHours(1));

			return userId;
		}

		public bool ResetPassword(int userId, string secret, string newPassword = null)
		{
			if(string.IsNullOrEmpty(secret))
				return false;

			var cache = this.EnsureService<Zongsoft.Runtime.Caching.ICache>();
			var cachedSecret = cache.GetValue(this.GetCacheKeyOfResetPassword(userId)) as string;
			var succeed = cachedSecret != null && string.Equals(secret, cachedSecret, StringComparison.Ordinal);

			if(succeed && newPassword != null && newPassword.Length > 0)
			{
				var dataAccess = this.EnsureService<IDataAccess>();

				//重新生成密码随机数
				var passwordSalt = Zongsoft.Common.RandomGenerator.Generate(8);

				var affectedRows = dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
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

			var userId = 0;
			var dataAccess = this.EnsureService<IDataAccess>();

			if(!MembershipHelper.GetUserId(dataAccess, identity, @namespace, out userId))
				return false;

			var cache = this.EnsureService<Zongsoft.Runtime.Caching.ICache>();
			var cachedSecret = cache.GetValue(this.GetCacheKeyOfResetPassword(userId)) as string;
			var succeed = cachedSecret != null && string.Equals(cachedSecret, secret, StringComparison.Ordinal);

			if(succeed && newPassword != null && newPassword.Length > 0)
			{
				//重新生成密码随机数
				var passwordSalt = Zongsoft.Common.RandomGenerator.Generate(8);

				var affectedRows = dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
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

			var dataAccess = this.EnsureService<IDataAccess>();
			var conditions = MembershipHelper.GetUserIdentityConditions(identity, @namespace);
			var record = dataAccess.Select<IDictionary<string, object>>(MembershipHelper.DATA_ENTITY_USER, conditions, "!, UserId, PasswordAnswer1, PasswordAnswer2, PasswordAnswer3").FirstOrDefault();

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

				return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
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
			var dataAccess = this.EnsureService<IDataAccess>();
			var record = dataAccess.Select<IDictionary<string, object>>(MembershipHelper.DATA_ENTITY_USER, new Condition("UserId", userId), "!, UserId, PasswordQuestion1, PasswordQuestion2, PasswordQuestion3").FirstOrDefault();

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
			var dataAccess = this.EnsureService<IDataAccess>();
			var conditions = MembershipHelper.GetUserIdentityConditions(identity, @namespace);
			var record = dataAccess.Select<IDictionary<string, object>>(MembershipHelper.DATA_ENTITY_USER, conditions, "!, UserId, PasswordQuestion1, PasswordQuestion2, PasswordQuestion3").FirstOrDefault();

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

			var dataAccess = this.EnsureService<IDataAccess>();

			byte[] storedPassword;
			byte[] storedPasswordSalt;
			bool isApproved, isSuspended;

			if(!MembershipHelper.GetPassword(dataAccess, userId, out storedPassword, out storedPasswordSalt, out isApproved, out isSuspended))
				return false;

			if(!PasswordUtility.VerifyPassword(password, storedPassword, storedPasswordSalt))
				return false;

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER, new
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
			var dataAccess = this.EnsureService<IDataAccess>();

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

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER, dictionary, new Condition("UserId", userId)) > 0;
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
