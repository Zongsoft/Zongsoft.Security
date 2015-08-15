﻿/*
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
	public class UserProvider : MembershipProviderBase, IUserProvider
	{
		#region 成员字段
		private ICensorship _censorship;
		private Zongsoft.Common.ISequence _sequence;
		private Zongsoft.Runtime.Caching.ICache _cache;
		#endregion

		#region 构造函数
		public UserProvider()
		{
		}
		#endregion

		#region 公共属性
		public Zongsoft.Common.ISequence Sequence
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

		public Zongsoft.Runtime.Caching.ICache Cache
		{
			get
			{
				return _cache;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_cache = value;
			}
		}

		public ICensorship Censorship
		{
			get
			{
				return _censorship;
			}
			set
			{
				if(value == null)
					throw new ArgumentNullException();

				_censorship = value;
			}
		}
		#endregion

		#region 用户管理
		public User GetUser(int userId)
		{
			var dataAccess = this.EnsureDataAccess();
			return MembershipHelper.GetUser(dataAccess, userId);
		}

		public User GetUser(string identity, string @namespace)
		{
			var dataAccess = this.EnsureDataAccess();
			var conditions = MembershipHelper.GetUserIdentityConditions(identity, @namespace);
			return dataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, conditions).FirstOrDefault();
		}

		public bool Exists(string identity, string @namespace)
		{
			var dataAccess = this.EnsureDataAccess();
			var conditions = MembershipHelper.GetUserIdentityConditions(identity, @namespace);
			return dataAccess.Count(MembershipHelper.DATA_ENTITY_USER, conditions) > 0;
		}

		public IEnumerable<User> GetAllUsers(string @namespace, Paging paging = null)
		{
			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Select<User>(MembershipHelper.DATA_ENTITY_USER, new Condition("Namespace", MembershipHelper.TrimNamespace(@namespace)), null, paging ?? new Paging(1, 20));
		}

		public bool SetPrincipal(int userId, string principal)
		{
			var dataAccess = this.EnsureDataAccess();

			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
				new { Principal = principal },
				new Condition("UserId", userId)) > 0;
		}

		public int DeleteUsers(params int[] userIds)
		{
			if(userIds == null || userIds.Length < 1)
				return 0;

			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Delete(MembershipHelper.DATA_ENTITY_USER, new Condition("UserId", userIds, ConditionOperator.In));
		}

		public bool CreateUser(User user, string password)
		{
			if(user == null)
				throw new ArgumentNullException("user");

			if(user.UserId < 1)
			{
				var sequence = this.Sequence;

				if(sequence == null)
					throw new MissingMemberException(this.GetType().FullName, "Sequence");

				user.UserId = (int)sequence.GetSequenceNumber(MembershipHelper.SEQUENCE_USERID, 1, MembershipHelper.MINIMUM_ID);
			}

			//确保所有用户名是有效的
			MembershipHelper.EnsureName(user.Name);

			//确保用户名是审核通过的
			if(_censorship != null && _censorship.IsBlocked(user.Name, Zongsoft.Security.Censorship.KEY_NAME, Zongsoft.Security.Censorship.KEY_SENSITIVES))
				throw new InvalidOperationException(string.Format("Illegal '{0}' name of user.", user.Name));

			var dataAccess = this.EnsureDataAccess();

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

				if(user.UserId < 1)
				{
					var sequence = this.Sequence;

					if(sequence == null)
						throw new MissingMemberException(this.GetType().FullName, "Sequence");

					user.UserId = (int)sequence.GetSequenceNumber(MembershipHelper.SEQUENCE_USERID, 1, MembershipHelper.MINIMUM_ID);
				}

				//确保所有用户名是有效的
				MembershipHelper.EnsureName(user.Name);

				//确保用户名是审核通过的
				if(_censorship != null && _censorship.IsBlocked(user.Name, Zongsoft.Security.Censorship.KEY_NAME, Zongsoft.Security.Censorship.KEY_SENSITIVES))
					throw new InvalidOperationException(string.Format("Illegal '{0}' name of user.", user.Name));
			}

			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Insert(MembershipHelper.DATA_ENTITY_USER, users);
		}

		public int UpdateUsers(params User[] users)
		{
			return this.UpdateUsers((IEnumerable<User>)users);
		}

		public int UpdateUsers(IEnumerable<User> users)
		{
			if(users == null)
				return 0;

			foreach(var user in users)
			{
				//确保所有用户名是有效的
				MembershipHelper.EnsureName(user.Name);
			}

			var dataAccess = this.EnsureDataAccess();
			return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER, users);
		}
		#endregion

		#region 密码管理
		public bool ChangePassword(int userId, string oldPassword, string newPassword)
		{
			var dataAccess = this.EnsureDataAccess();

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

		public bool ForgetPassword(string identity, string @namespace, out int userId, out string secret, out string token)
		{
			userId = 0;
			secret = null;
			token = null;

			var dataAccess = this.EnsureDataAccess();

			if(!MembershipHelper.GetUserId(dataAccess, identity, @namespace, out userId))
				return false;

			secret = Zongsoft.Common.RandomGenerator.GenerateInt64().ToString();

			if(secret.Length > 6)
				secret = secret.Substring(0, 6);

			var cache = this.EnsureCache();

			if(!cache.SetValue(this.GetCacheKeyOfResetPassword(userId), secret, TimeSpan.FromHours(24), true))
				secret = cache.GetValue(this.GetCacheKeyOfResetPassword(userId)) as string;

			token = this.GetSecretToken(userId, secret);

			return secret != null && secret.Length > 0;
		}

		public bool ResetPassword(int userId, string token, string newPassword = null)
		{
			if(string.IsNullOrEmpty(token))
				return false;

			var cache = this.EnsureCache();
			var secret = cache.GetValue(this.GetCacheKeyOfResetPassword(userId)) as string;
			var result = secret != null && string.Equals(token, this.GetSecretToken(userId, secret), StringComparison.Ordinal);

			if(result && newPassword != null && newPassword.Length > 0)
			{
				var dataAccess = this.EnsureDataAccess();

				//重新生成密码随机数
				var passwordSalt = Zongsoft.Common.RandomGenerator.Generate(8);

				return dataAccess.Update(MembershipHelper.DATA_ENTITY_USER,
					new
					{
						Password = PasswordUtility.HashPassword(newPassword, passwordSalt),
						PasswordSalt = passwordSalt,
					}, new Condition("UserId", userId)) > 0;
			}

			return result;
		}

		public bool ResetPassword(string identity, string @namespace, string secret, string newPassword = null)
		{
			if(string.IsNullOrWhiteSpace(identity) || string.IsNullOrWhiteSpace(secret))
				return false;

			var userId = 0;
			var dataAccess = this.EnsureDataAccess();

			if(!MembershipHelper.GetUserId(dataAccess, identity, @namespace, out userId))
				return false;

			var cache = this.EnsureCache();
			var cachedSecret = cache.GetValue(this.GetCacheKeyOfResetPassword(userId)) as string;
			var result = cachedSecret != null && string.Equals(cachedSecret, secret, StringComparison.Ordinal);

			if(result && newPassword != null && newPassword.Length > 0)
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

			return result;
		}

		public bool ResetPassword(string identity, string @namespace, string[] passwordAnswers, string newPassword = null)
		{
			if(string.IsNullOrWhiteSpace(identity) || passwordAnswers == null || passwordAnswers.Length != 3)
				return false;

			var dataAccess = this.EnsureDataAccess();
			var conditions = MembershipHelper.GetUserIdentityConditions(identity, @namespace);
			var record = dataAccess.Select<IDictionary<string, object>>(MembershipHelper.DATA_ENTITY_USER, conditions, "!, UserId, PasswordAnswer1, PasswordAnswer2, PasswordAnswer3").FirstOrDefault();

			if(record == null || record.Count < 1)
				return false;

			var userId = Zongsoft.Common.Convert.ConvertValue<int>(record["UserId"]);

			var result = (string.Equals(passwordAnswers[0], (string)record["PasswordAnswer1"], StringComparison.Ordinal) &&
			              string.Equals(passwordAnswers[1], (string)record["PasswordAnswer2"], StringComparison.Ordinal) &&
			              string.Equals(passwordAnswers[2], (string)record["PasswordAnswer3"], StringComparison.Ordinal));

			if(result && newPassword != null && newPassword.Length > 0)
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

			return result;
		}

		public string[] GetPasswordQuestions(string identity, string @namespace)
		{
			var dataAccess = this.EnsureDataAccess();
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
			if(passwordQuestions == null || passwordQuestions.Length == 0)
				throw new ArgumentNullException("passwordQuestions");

			if(passwordAnswers == null || passwordAnswers.Length == 0)
				throw new ArgumentNullException("passwordAnswers");

			if(passwordQuestions.Length != passwordAnswers.Length)
				throw new ArgumentException();

			var dataAccess = this.EnsureDataAccess();

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
				PasswordAnswer1 = passwordAnswers.Length > 0 ? passwordAnswers[0] : null,
				PasswordQuestion2 = passwordQuestions.Length > 1 ? passwordQuestions[1] : null,
				PasswordAnswer2 = passwordAnswers.Length > 1 ? passwordAnswers[1] : null,
				PasswordQuestion3 = passwordQuestions.Length > 2 ? passwordQuestions[2] : null,
				PasswordAnswer3 = passwordAnswers.Length > 2 ? passwordAnswers[2] : null,
			}, new Condition("UserId", userId)) > 0;
		}
		#endregion

		#region 私有方法
		private Zongsoft.Runtime.Caching.ICache EnsureCache()
		{
			var cache = this.Cache;

			if(cache == null)
				throw new MissingMemberException(this.GetType().FullName, "Cache");

			return cache;
		}

		private string GetSecretToken(int userId, string secret)
		{
			if(string.IsNullOrEmpty(secret))
				return null;

			using(var hash = System.Security.Cryptography.MD5.Create())
			{
				var code = hash.ComputeHash(Encoding.ASCII.GetBytes(userId.ToString() + secret));
				return Zongsoft.Common.Convert.ToHexString(code);
			}
		}

		private string GetCacheKeyOfResetPassword(int userId)
		{
			return "Zongsoft.Security.Membership.ResetPassword:" + userId.ToString();
		}
		#endregion
	}
}
