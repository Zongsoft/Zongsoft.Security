/*
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@gmail.com>
 *
 * Copyright (C) 2015-2018 Zongsoft Corporation <http://www.zongsoft.com>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
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

namespace Zongsoft.Security.Web
{
	internal static class Utility
	{
		/// <summary>
		/// 确认指定的标识模式文本是否为编号（即一个整数）。
		/// </summary>
		/// <param name="pattern">待解析的标识模式文本。</param>
		/// <param name="identity">如果指定的<paramref name="pattern"/>参数值不是数字，则为其中的标识部分。</param>
		/// <param name="prefix">如果指定<paramref name="pattern"/>参数值不是数字，则为其中的前缀部分，前缀以冒号(:)分隔。</param>
		/// <param name="suffix">如果指定<paramref name="pattern"/>参数值不是数字，则为其中的后缀部分，后缀以叹号(!)分隔。</param>
		/// <returns>如果指定的<paramref name="pattern"/>参数值是数字则返回其对应的数值，否则返回零。</returns>
		public static uint ResolvePattern(string pattern, out string identity, out string prefix, out string suffix)
		{
			prefix = null;
			suffix = null;
			identity = null;

			if(string.IsNullOrWhiteSpace(pattern))
				return 0;

			if(uint.TryParse(pattern, out var id))
				return id;

			var prefixIndex = pattern.IndexOf(':');
			var suffixIndex = pattern.LastIndexOf('!');

			if(suffixIndex > 0 && suffixIndex > prefixIndex)
			{
				identity = pattern.Substring(prefixIndex + 1, suffixIndex - prefixIndex - 1);
				suffix = pattern.Substring(suffixIndex + 1);
			}
			else
			{
				identity = pattern.Substring(prefixIndex + 1);
			}

			if(prefixIndex > 0)
				prefix = pattern.Substring(0, prefixIndex);

			return 0;
		}

		public static string GetDataSchema(this System.Net.Http.HttpRequestMessage request)
		{
			return GetHttpHeaderValue(request.Headers, "x-data-schema");
		}

		public static string GetHttpHeaderValue(this System.Net.Http.Headers.HttpHeaders headers, string name)
		{
			if(headers != null && headers.TryGetValues(name, out var values) && values != null)
				return string.Join("", values);

			return null;
		}
	}
}
