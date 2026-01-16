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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import packetproxy.extensions.securityheaders.SecurityCheck;
import packetproxy.extensions.securityheaders.SecurityCheck.HighlightSegment;
import packetproxy.extensions.securityheaders.SecurityCheck.HighlightType;
import packetproxy.extensions.securityheaders.SecurityCheckResult;
import packetproxy.http.HttpHeader;

public class HighlightSegmentTest {

	// ===== HighlightSegment Construction =====

	@Test
	public void testHighlightSegment_BasicConstruction() {
		HighlightSegment segment = new HighlightSegment(0, 10, HighlightType.GREEN);
		assertEquals(0, segment.getStart());
		assertEquals(10, segment.getEnd());
		assertEquals(HighlightType.GREEN, segment.getType());
	}

	@Test
	public void testHighlightSegment_ZeroLength() {
		HighlightSegment segment = new HighlightSegment(5, 5, HighlightType.RED);
		assertEquals(5, segment.getStart());
		assertEquals(5, segment.getEnd());
	}

	@Test
	public void testHighlightSegment_NegativeIndices() {
		// Constructor doesn't validate, so negative values are allowed
		HighlightSegment segment = new HighlightSegment(-1, -1, HighlightType.YELLOW);
		assertEquals(-1, segment.getStart());
		assertEquals(-1, segment.getEnd());
	}

	@Test
	public void testHighlightSegment_StartGreaterThanEnd() {
		// Constructor doesn't validate order
		HighlightSegment segment = new HighlightSegment(10, 5, HighlightType.RED);
		assertEquals(10, segment.getStart());
		assertEquals(5, segment.getEnd());
	}

	// ===== HighlightType Values =====

	@Test
	public void testHighlightType_AllValues() {
		assertEquals(4, HighlightType.values().length);
		assertNotNull(HighlightType.GREEN);
		assertNotNull(HighlightType.RED);
		assertNotNull(HighlightType.YELLOW);
		assertNotNull(HighlightType.NONE);
	}

	// ===== getHighlightType Default Implementation =====

	@Test
	public void testGetHighlightType_NullResult_ReturnsNone() {
		SecurityCheck testCheck = createTestCheck("test-header:", Collections.emptyList());
		HighlightType type = testCheck.getHighlightType("test-header: value", null);
		assertEquals(HighlightType.NONE, type);
	}

	@Test
	public void testGetHighlightType_NonMatchingHeader_ReturnsNone() {
		SecurityCheck testCheck = createTestCheck("test-header:", Collections.emptyList());
		SecurityCheckResult result = SecurityCheckResult.ok("ok", "ok");
		HighlightType type = testCheck.getHighlightType("other-header: value", result);
		assertEquals(HighlightType.NONE, type);
	}

	@Test
	public void testGetHighlightType_OkResult_ReturnsGreen() {
		SecurityCheck testCheck = createTestCheck("test-header:", Collections.emptyList());
		SecurityCheckResult result = SecurityCheckResult.ok("ok", "ok");
		HighlightType type = testCheck.getHighlightType("test-header: value", result);
		assertEquals(HighlightType.GREEN, type);
	}

	@Test
	public void testGetHighlightType_FailResult_ReturnsRed() {
		SecurityCheck testCheck = createTestCheck("test-header:", Collections.emptyList());
		SecurityCheckResult result = SecurityCheckResult.fail("fail", "fail");
		HighlightType type = testCheck.getHighlightType("test-header: value", result);
		assertEquals(HighlightType.RED, type);
	}

	@Test
	public void testGetHighlightType_WarnResult_ReturnsYellow() {
		SecurityCheck testCheck = createTestCheck("test-header:", Collections.emptyList());
		SecurityCheckResult result = SecurityCheckResult.warn("warn", "warn");
		HighlightType type = testCheck.getHighlightType("test-header: value", result);
		assertEquals(HighlightType.YELLOW, type);
	}

	// ===== getHighlightSegments Default Implementation =====

	@Test
	public void testGetHighlightSegments_NonMatchingHeader_ReturnsEmpty() {
		SecurityCheck testCheck = createTestCheck("test-header:", Collections.emptyList());
		SecurityCheckResult result = SecurityCheckResult.ok("ok", "ok");
		List<HighlightSegment> segments = testCheck.getHighlightSegments("other-header: value", result);
		assertTrue(segments.isEmpty());
	}

	@Test
	public void testGetHighlightSegments_NoPatterns_ReturnsEmpty() {
		SecurityCheck testCheck = createTestCheck("test-header:", Collections.emptyList());
		SecurityCheckResult result = SecurityCheckResult.ok("ok", "ok");
		List<HighlightSegment> segments = testCheck.getHighlightSegments("test-header: value", result);
		assertTrue(segments.isEmpty());
	}

	@Test
	public void testGetHighlightSegments_WithGreenPattern_ReturnsSegments() {
		SecurityCheck testCheck = createTestCheckWithPatterns("test-header:", Collections.emptyList(),
				Collections.emptyList(), Arrays.asList("safe"));
		SecurityCheckResult result = SecurityCheckResult.ok("ok", "ok");
		List<HighlightSegment> segments = testCheck.getHighlightSegments("test-header: safe", result);
		assertFalse(segments.isEmpty());
	}

	@Test
	public void testGetHighlightSegments_EmptyLine_ReturnsEmpty() {
		SecurityCheck testCheck = createTestCheck("", Arrays.asList("pattern"));
		SecurityCheckResult result = SecurityCheckResult.ok("ok", "ok");
		List<HighlightSegment> segments = testCheck.getHighlightSegments("", result);
		assertTrue(segments.isEmpty());
	}

	// ===== Pattern Priority Tests =====

	@Test
	public void testGetHighlightSegments_GreenOverridesRed() {
		SecurityCheck testCheck = createTestCheckWithPatterns("test:", Arrays.asList("value"), // red
				Collections.emptyList(), // yellow
				Arrays.asList("value")); // green (higher priority)
		SecurityCheckResult result = SecurityCheckResult.ok("ok", "ok");
		List<HighlightSegment> segments = testCheck.getHighlightSegments("test: value", result);

		// Green should win due to higher priority
		boolean hasGreen = segments.stream().anyMatch(s -> s.getType() == HighlightType.GREEN);
		assertTrue(hasGreen);
	}

	// ===== affectsOverallStatus Default =====

	@Test
	public void testAffectsOverallStatus_DefaultTrue() {
		SecurityCheck testCheck = createTestCheck("test:", Collections.emptyList());
		assertTrue(testCheck.affectsOverallStatus());
	}

	// ===== Helper Methods =====

	private SecurityCheck createTestCheck(String headerPrefix, List<String> redPatterns) {
		return createTestCheckWithPatterns(headerPrefix, redPatterns, Collections.emptyList(), Collections.emptyList());
	}

	private SecurityCheck createTestCheckWithPatterns(String headerPrefix, List<String> redPatterns,
			List<String> yellowPatterns, List<String> greenPatterns) {
		return new SecurityCheck() {
			@Override
			public String getName() {
				return "Test";
			}

			@Override
			public String getColumnName() {
				return "Test";
			}

			@Override
			public String getMissingMessage() {
				return "Test missing";
			}

			@Override
			public SecurityCheckResult check(HttpHeader header, Map<String, Object> context) {
				return SecurityCheckResult.ok("ok", "ok");
			}

			@Override
			public boolean matchesHeaderLine(String headerLine) {
				return headerLine.toLowerCase().startsWith(headerPrefix.toLowerCase());
			}

			@Override
			public List<String> getRedPatterns() {
				return redPatterns;
			}

			@Override
			public List<String> getYellowPatterns() {
				return yellowPatterns;
			}

			@Override
			public List<String> getGreenPatterns() {
				return greenPatterns;
			}
		};
	}
}
