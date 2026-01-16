/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy.extensions.securityheaders.test;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import packetproxy.extensions.securityheaders.SecurityCheckResult;
import packetproxy.extensions.securityheaders.checks.CookieCheck;
import packetproxy.http.HttpHeader;

public class CookieCheckTest {

	private CookieCheck check;
	private Map<String, Object> context;

	@BeforeEach
	public void setUp() {
		check = new CookieCheck();
		context = new HashMap<>();
	}

	// ===== No Cookie Cases =====

	@Test
	public void testCheck_NoCookies_Ok() {
		HttpHeader header = TestHttpHeader.empty();
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
		assertEquals("No cookies", result.getDisplayValue());
	}

	// ===== Missing Secure Flag =====

	@Test
	public void testCheck_CookieWithoutSecure_Fail() {
		HttpHeader header = TestHttpHeader.withSetCookie("session=abc123; HttpOnly");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
	}

	@Test
	public void testCheck_CookieWithHttpOnlyOnly_Fail() {
		HttpHeader header = TestHttpHeader.withSetCookie("token=xyz; HttpOnly; Path=/");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
	}

	@Test
	public void testCheck_SimpleCookieWithoutAttributes_Fail() {
		HttpHeader header = TestHttpHeader.withSetCookie("name=value");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
	}

	// ===== Multiple Cookies - Mixed Secure Status =====

	@Test
	public void testCheck_MultipleCookies_OneWithoutSecure_Fail() {
		HttpHeader header = new TestHttpHeader().addHeader("Set-Cookie", "cookie1=value1; Secure")
				.addHeader("Set-Cookie", "cookie2=value2; HttpOnly").build();
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
	}

	@Test
	public void testCheck_MultipleCookies_AllWithoutSecure_Fail() {
		HttpHeader header = new TestHttpHeader().addHeader("Set-Cookie", "cookie1=value1")
				.addHeader("Set-Cookie", "cookie2=value2").addHeader("Set-Cookie", "cookie3=value3").build();
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
	}

	// ===== Edge Cases with Secure Flag Position =====

	@Test
	public void testCheck_SecureAtBeginning_Fail() {
		// Malformed: "Secure" at beginning without space prefix
		HttpHeader header = TestHttpHeader.withSetCookie("Secure; session=abc123");
		SecurityCheckResult result = check.check(header, context);

		// Implementation checks for " secure" (with space), so this fails
		assertTrue(result.isFail());
	}

	@Test
	public void testCheck_SecureInValue_Fail() {
		// "secure" appears in cookie value, not as attribute
		HttpHeader header = TestHttpHeader.withSetCookie("data=this_is_secure_data");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail()); // " secure" (with space) not found
	}

	@Test
	public void testCheck_SecureFlagWithDifferentCase_Ok() {
		HttpHeader header = TestHttpHeader.withSetCookie("session=abc123; SECURE");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_SecureFlagMixedCase_Ok() {
		HttpHeader header = TestHttpHeader.withSetCookie("session=abc123; SeCuRe");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	// ===== Valid Cookie Cases =====

	@Test
	public void testCheck_CookieWithSecure_Ok() {
		HttpHeader header = TestHttpHeader.withSetCookie("session=abc123; Secure; HttpOnly");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_MultipleCookies_AllSecure_Ok() {
		HttpHeader header = new TestHttpHeader().addHeader("Set-Cookie", "cookie1=value1; Secure")
				.addHeader("Set-Cookie", "cookie2=value2; Secure; HttpOnly").build();
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	// ===== Context Storage =====

	@Test
	@SuppressWarnings("unchecked")
	public void testCheck_StoresCookiesInContext() {
		HttpHeader header = new TestHttpHeader().addHeader("Set-Cookie", "cookie1=value1; Secure")
				.addHeader("Set-Cookie", "cookie2=value2").build();
		check.check(header, context);

		List<String> cookies = (List<String>) context.get(CookieCheck.CONTEXT_KEY);
		assertNotNull(cookies);
		assertEquals(2, cookies.size());
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testCheck_NoCookies_StoresEmptyListInContext() {
		HttpHeader header = TestHttpHeader.empty();
		check.check(header, context);

		List<String> cookies = (List<String>) context.get(CookieCheck.CONTEXT_KEY);
		assertNotNull(cookies);
		assertTrue(cookies.isEmpty());
	}

	// ===== Display Value Truncation =====

	@Test
	public void testCheck_LongCookieValue_Truncated() {
		String longValue = "a".repeat(100);
		HttpHeader header = TestHttpHeader.withSetCookie("session=" + longValue + "; Secure");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
		assertTrue(result.getDisplayValue().contains("..."));
	}

	// ===== Static hasSecureFlag Method =====

	@Test
	public void testHasSecureFlag_WithSecure_True() {
		assertTrue(CookieCheck.hasSecureFlag("set-cookie: session=abc; secure"));
	}

	@Test
	public void testHasSecureFlag_WithoutSecure_False() {
		assertFalse(CookieCheck.hasSecureFlag("set-cookie: session=abc; httponly"));
	}

	@Test
	public void testHasSecureFlag_EmptyString_False() {
		assertFalse(CookieCheck.hasSecureFlag(""));
	}

	@Test
	public void testHasSecureFlag_SecureInValue_True() {
		// Note: This is a known limitation - it checks for substring
		assertTrue(CookieCheck.hasSecureFlag("set-cookie: data=secure_value"));
	}

	// ===== matchesHeaderLine =====

	@Test
	public void testMatchesHeaderLine_SetCookie_True() {
		assertTrue(check.matchesHeaderLine("set-cookie: session=abc"));
	}

	@Test
	public void testMatchesHeaderLine_OtherHeader_False() {
		assertFalse(check.matchesHeaderLine("cookie: session=abc"));
	}

	@Test
	public void testMatchesHeaderLine_EmptyString_False() {
		assertFalse(check.matchesHeaderLine(""));
	}
}
