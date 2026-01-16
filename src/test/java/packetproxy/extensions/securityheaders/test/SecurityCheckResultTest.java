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

import org.junit.jupiter.api.Test;
import packetproxy.extensions.securityheaders.SecurityCheckResult;

public class SecurityCheckResultTest {

	// ===== Constructor - Abnormal Cases =====

	@Test
	public void testConstructor_NullStatus_ThrowsException() {
		assertThrows(IllegalArgumentException.class, () -> {
			new SecurityCheckResult(null, "display", "raw");
		});
	}

	@Test
	public void testConstructor_NullDisplayValue_SetsDefault() {
		SecurityCheckResult result = new SecurityCheckResult(SecurityCheckResult.Status.OK, null, "raw");
		assertEquals("OK", result.getDisplayValue());
	}

	@Test
	public void testConstructor_NullRawValue_SetsEmptyString() {
		SecurityCheckResult result = new SecurityCheckResult(SecurityCheckResult.Status.FAIL, "display", null);
		assertEquals("", result.getRawValue());
	}

	@Test
	public void testConstructor_AllNullExceptStatus_SetsDefaults() {
		SecurityCheckResult result = new SecurityCheckResult(SecurityCheckResult.Status.FAIL, null, null);
		assertEquals("FAIL", result.getDisplayValue());
		assertEquals("", result.getRawValue());
	}

	@Test
	public void testConstructor_WarnStatus_NullDisplay_SetsWarnDefault() {
		SecurityCheckResult result = new SecurityCheckResult(SecurityCheckResult.Status.WARN, null, null);
		assertEquals("WARN", result.getDisplayValue());
	}

	// ===== Static Factory Methods - Edge Cases =====

	@Test
	public void testOk_EmptyStrings() {
		SecurityCheckResult result = SecurityCheckResult.ok("", "");
		assertTrue(result.isOk());
		assertEquals("", result.getDisplayValue());
		assertEquals("", result.getRawValue());
	}

	@Test
	public void testFail_EmptyStrings() {
		SecurityCheckResult result = SecurityCheckResult.fail("", "");
		assertTrue(result.isFail());
		assertEquals("", result.getDisplayValue());
	}

	@Test
	public void testWarn_EmptyStrings() {
		SecurityCheckResult result = SecurityCheckResult.warn("", "");
		assertTrue(result.isWarn());
	}

	@Test
	public void testOk_NullValues() {
		SecurityCheckResult result = SecurityCheckResult.ok(null, null);
		assertTrue(result.isOk());
		assertEquals("OK", result.getDisplayValue());
		assertEquals("", result.getRawValue());
	}

	@Test
	public void testFail_NullValues() {
		SecurityCheckResult result = SecurityCheckResult.fail(null, null);
		assertTrue(result.isFail());
		assertEquals("FAIL", result.getDisplayValue());
	}

	@Test
	public void testWarn_NullValues() {
		SecurityCheckResult result = SecurityCheckResult.warn(null, null);
		assertTrue(result.isWarn());
		assertEquals("WARN", result.getDisplayValue());
	}

	// ===== Status Methods - Mutual Exclusivity =====

	@Test
	public void testStatusMutualExclusivity_Ok() {
		SecurityCheckResult result = SecurityCheckResult.ok("test", "test");
		assertTrue(result.isOk());
		assertFalse(result.isFail());
		assertFalse(result.isWarn());
	}

	@Test
	public void testStatusMutualExclusivity_Fail() {
		SecurityCheckResult result = SecurityCheckResult.fail("test", "test");
		assertFalse(result.isOk());
		assertTrue(result.isFail());
		assertFalse(result.isWarn());
	}

	@Test
	public void testStatusMutualExclusivity_Warn() {
		SecurityCheckResult result = SecurityCheckResult.warn("test", "test");
		assertFalse(result.isOk());
		assertFalse(result.isFail());
		assertTrue(result.isWarn());
	}

	// ===== Edge Cases with Special Characters =====

	@Test
	public void testConstructor_SpecialCharactersInValues() {
		String specialChars = "テスト<script>alert('xss')</script>\n\r\t";
		SecurityCheckResult result = SecurityCheckResult.ok(specialChars, specialChars);
		assertEquals(specialChars, result.getDisplayValue());
		assertEquals(specialChars, result.getRawValue());
	}

	@Test
	public void testConstructor_VeryLongStrings() {
		String longString = "a".repeat(10000);
		SecurityCheckResult result = SecurityCheckResult.ok(longString, longString);
		assertEquals(longString, result.getDisplayValue());
		assertEquals(longString, result.getRawValue());
	}

	@Test
	public void testConstructor_WhitespaceOnlyStrings() {
		SecurityCheckResult result = SecurityCheckResult.ok("   ", "\t\n\r");
		assertEquals("   ", result.getDisplayValue());
		assertEquals("\t\n\r", result.getRawValue());
	}
}
