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
import packetproxy.extensions.securityheaders.checks.ContentTypeCheck;
import packetproxy.http.HttpHeader;

public class ContentTypeCheckTest {

	private ContentTypeCheck check;
	private Map<String, Object> context;

	@BeforeEach
	public void setUp() {
		check = new ContentTypeCheck();
		context = new HashMap<>();
	}

	// ===== Missing Header Cases =====

	@Test
	public void testCheck_NoContentTypeHeader_Ok() {
		// Missing header is treated as OK (non-HTML)
		HttpHeader header = TestHttpHeader.empty();
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	// ===== text/html without charset =====

	@Test
	public void testCheck_TextHtmlWithoutCharset_Fail() {
		HttpHeader header = TestHttpHeader.withContentType("text/html");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
		assertEquals("No charset", result.getDisplayValue());
	}

	@Test
	public void testCheck_TextHtmlUppercaseWithoutCharset_Fail() {
		HttpHeader header = TestHttpHeader.withContentType("TEXT/HTML");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
	}

	@Test
	public void testCheck_TextHtmlMixedCaseWithoutCharset_Fail() {
		HttpHeader header = TestHttpHeader.withContentType("Text/Html");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
	}

	@Test
	public void testCheck_TextHtmlWithExtraParams_NoCharset_Fail() {
		HttpHeader header = TestHttpHeader.withContentType("text/html; boundary=something");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
	}

	// ===== Malformed charset =====

	@Test
	public void testCheck_TextHtmlWithEmptyCharset_Ok() {
		// "charset=" is present, even if empty
		HttpHeader header = TestHttpHeader.withContentType("text/html; charset=");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_TextHtmlWithCharsetInValue_Ok() {
		// Edge case: charset appears somewhere in value
		HttpHeader header = TestHttpHeader.withContentType("text/html; custom-charset=utf-8");
		SecurityCheckResult result = check.check(header, context);

		// This passes because it contains "charset="
		assertTrue(result.isOk());
	}

	// ===== Non-HTML Content Types =====

	@Test
	public void testCheck_ApplicationJson_Ok() {
		HttpHeader header = TestHttpHeader.withContentType("application/json");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
		assertEquals("application/json", result.getDisplayValue());
	}

	@Test
	public void testCheck_TextPlain_Ok() {
		HttpHeader header = TestHttpHeader.withContentType("text/plain");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_ImagePng_Ok() {
		HttpHeader header = TestHttpHeader.withContentType("image/png");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_ApplicationXml_Ok() {
		HttpHeader header = TestHttpHeader.withContentType("application/xml");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	// ===== Valid text/html with charset =====

	@Test
	public void testCheck_TextHtmlWithCharsetUtf8_Ok() {
		HttpHeader header = TestHttpHeader.withContentType("text/html; charset=utf-8");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
		assertEquals("text/html; charset=utf-8", result.getDisplayValue());
	}

	@Test
	public void testCheck_TextHtmlWithCharsetIso_Ok() {
		HttpHeader header = TestHttpHeader.withContentType("text/html; charset=ISO-8859-1");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_TextHtmlWithMultipleParams_Ok() {
		HttpHeader header = TestHttpHeader.withContentType("text/html; charset=utf-8; boundary=something");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	// ===== Edge Cases =====

	@Test
	public void testCheck_EmptyContentType_Ok() {
		HttpHeader header = TestHttpHeader.withContentType("");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_WhitespaceOnlyContentType_Ok() {
		HttpHeader header = TestHttpHeader.withContentType("   ");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_TextHtmlxWithoutCharset_Fail() {
		// "text/htmlx" contains "text/html" substring, so charset is required
		HttpHeader header = TestHttpHeader.withContentType("text/htmlx");
		SecurityCheckResult result = check.check(header, context);

		// Implementation uses contains() so this matches text/html
		assertTrue(result.isFail());
	}

	@Test
	public void testCheck_ApplicationXhtmlXml_Ok() {
		// XHTML is not exactly "text/html"
		HttpHeader header = TestHttpHeader.withContentType("application/xhtml+xml");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	// ===== matchesHeaderLine =====

	@Test
	public void testMatchesHeaderLine_ContentType_True() {
		assertTrue(check.matchesHeaderLine("content-type: text/html"));
	}

	@Test
	public void testMatchesHeaderLine_OtherHeader_False() {
		assertFalse(check.matchesHeaderLine("cache-control: no-cache"));
	}

	@Test
	public void testMatchesHeaderLine_EmptyString_False() {
		assertFalse(check.matchesHeaderLine(""));
	}

	// ===== Name and Messages =====

	@Test
	public void testGetName() {
		assertEquals("Content-Type", check.getName());
	}

	@Test
	public void testGetColumnName() {
		assertEquals("Content-Type", check.getColumnName());
	}

	@Test
	public void testGetMissingMessage() {
		assertEquals("Content-Type header is missing charset for text/html", check.getMissingMessage());
	}
}
