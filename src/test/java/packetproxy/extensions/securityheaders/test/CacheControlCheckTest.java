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
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import packetproxy.extensions.securityheaders.SecurityCheckResult;
import packetproxy.extensions.securityheaders.checks.CacheControlCheck;
import packetproxy.http.HttpHeader;

public class CacheControlCheckTest {

	private CacheControlCheck check;
	private Map<String, Object> context;

	@BeforeEach
	public void setUp() {
		check = new CacheControlCheck();
		context = new HashMap<>();
	}

	// ===== No Cache-Control Header =====

	@Test
	public void testCheck_NoCacheControlNoPragma_Ok() {
		HttpHeader header = TestHttpHeader.empty();
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
		assertEquals("No Cache-Control or Pragma", result.getDisplayValue());
	}

	// ===== Incomplete Cache-Control =====

	@Test
	public void testCheck_OnlyPrivate_Warn() {
		HttpHeader header = TestHttpHeader.withCacheControl("private");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isWarn());
	}

	@Test
	public void testCheck_OnlyNoStore_Warn() {
		HttpHeader header = TestHttpHeader.withCacheControl("no-store");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isWarn());
	}

	@Test
	public void testCheck_OnlyNoCache_Warn() {
		HttpHeader header = TestHttpHeader.withCacheControl("no-cache");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isWarn());
	}

	@Test
	public void testCheck_OnlyMustRevalidate_Warn() {
		HttpHeader header = TestHttpHeader.withCacheControl("must-revalidate");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isWarn());
	}

	@Test
	public void testCheck_PrivateAndNoStore_Warn() {
		HttpHeader header = TestHttpHeader.withCacheControl("private, no-store");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isWarn());
	}

	@Test
	public void testCheck_AllDirectivesButNoPragma_Warn() {
		// Has all Cache-Control directives but missing Pragma: no-cache
		HttpHeader header = TestHttpHeader.withCacheControl("private, no-store, no-cache, must-revalidate");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isWarn());
	}

	// ===== Pragma without Cache-Control =====

	@Test
	public void testCheck_OnlyPragmaNoCache_Warn() {
		HttpHeader header = new TestHttpHeader().addHeader("Pragma", "no-cache").build();
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isWarn());
	}

	// ===== Insecure Cache Configurations =====

	@Test
	public void testCheck_PublicCache_Warn() {
		HttpHeader header = TestHttpHeader.withCacheControl("public, max-age=3600");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isWarn());
	}

	@Test
	public void testCheck_MaxAgeOnly_Warn() {
		HttpHeader header = TestHttpHeader.withCacheControl("max-age=86400");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isWarn());
	}

	// ===== Secure Configuration =====

	@Test
	public void testCheck_FullSecureConfig_Ok() {
		HttpHeader header = new TestHttpHeader()
				.addHeader("Cache-Control", "private, no-store, no-cache, must-revalidate")
				.addHeader("Pragma", "no-cache").build();
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_FullSecureConfigWithExtraDirectives_Ok() {
		HttpHeader header = new TestHttpHeader()
				.addHeader("Cache-Control", "private, no-store, no-cache, must-revalidate, max-age=0")
				.addHeader("Pragma", "no-cache").build();
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	// ===== Edge Cases =====

	@Test
	public void testCheck_EmptyCacheControl_Ok() {
		HttpHeader header = TestHttpHeader.withCacheControl("");
		SecurityCheckResult result = check.check(header, context);

		// Empty string is treated as missing header
		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_WhitespaceOnlyCacheControl_Ok() {
		HttpHeader header = TestHttpHeader.withCacheControl("   ");
		SecurityCheckResult result = check.check(header, context);

		// Whitespace-only is treated as missing header
		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_CacheControlWithTypo_Warn() {
		// Misspelled directives
		HttpHeader header = TestHttpHeader.withCacheControl("privat, no-stor, no-cach, must-revalidat");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isWarn());
	}

	// ===== matchesHeaderLine =====

	@Test
	public void testMatchesHeaderLine_CacheControl_True() {
		assertTrue(check.matchesHeaderLine("cache-control: no-cache"));
	}

	@Test
	public void testMatchesHeaderLine_OtherHeader_False() {
		assertFalse(check.matchesHeaderLine("pragma: no-cache"));
	}

	@Test
	public void testMatchesHeaderLine_EmptyString_False() {
		assertFalse(check.matchesHeaderLine(""));
	}

	// ===== affectsOverallStatus =====

	@Test
	public void testAffectsOverallStatus_False() {
		assertFalse(check.affectsOverallStatus());
	}

	// ===== Name and Messages =====

	@Test
	public void testGetName() {
		assertEquals("Cache-Control", check.getName());
	}

	@Test
	public void testGetColumnName() {
		assertEquals("Cache-Control", check.getColumnName());
	}

	@Test
	public void testGetMissingMessage() {
		assertEquals("Cache-Control is not configured for sensitive data protection", check.getMissingMessage());
	}
}
